"""Subprocess isolation of the availability probes.

The probe must never import the probed module in-process: angr's
import chain reaches pypcode_native's C++ init, which can abort the
host uncatchably (SIGABRT) — Python cannot catch a signal raised
inside a C extension's init, so an in-process probe kills the whole
run (observed as full xdist worker node-down). These tests make the
hazard deterministic with a scratch module whose import calls
``os.abort()``: with an in-process probe the test process itself
dies with SIGABRT; with the isolated probe the child dies and the
caller gets a clean False.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from core.symbolic import _availability
from core.symbolic._availability import _probe, clear_probe_cache


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch: pytest.MonkeyPatch):
    """Probe results are memoized per process — isolate every test.

    Widens the probe allowlist so the synthetic module names these
    tests exercise (``json``, ``raptor_scratch_*``) pass the
    parent-side gate.
    """
    monkeypatch.setattr(
        _availability, "_ALLOWED_PROBE_MODULES",
        _availability._ALLOWED_PROBE_MODULES | {
            "json",
            "raptor_scratch_no_such_module",
            "raptor_scratch_abort_on_import",
            "raptor_scratch_sleep_on_import",
        },
    )
    clear_probe_cache()
    yield
    clear_probe_cache()


@pytest.fixture()
def scratch_import_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make ``tmp_path`` importable by BOTH the test process and any
    probe child: sys.path for in-process imports, PYTHONPATH for the
    spawned interpreter (the probe child inherits the parent env).
    """
    monkeypatch.syspath_prepend(str(tmp_path))
    existing = os.environ.get("PYTHONPATH")
    joined = (
        str(tmp_path) if not existing
        else str(tmp_path) + os.pathsep + existing
    )
    monkeypatch.setenv("PYTHONPATH", joined)
    return tmp_path


def test_probe_stdlib_module_available() -> None:
    """Success path: a stdlib module probes True."""
    assert _probe("scratch-json", "json") is True


def test_probe_nonexistent_module_unavailable() -> None:
    """Failure path: a module that does not exist probes False."""
    assert _probe("scratch-nope", "raptor_scratch_no_such_module") is False


def test_probe_survives_import_that_aborts_the_process(
    scratch_import_path: Path,
) -> None:
    """The registered hazard, made deterministic: a module whose
    import calls ``os.abort()``. An in-process probe dies with
    SIGABRT here (killing the pytest worker); the isolated probe
    maps the child's signal death to False and the caller survives.
    """
    mod = scratch_import_path / "raptor_scratch_abort_on_import.py"
    mod.write_text("import os\nos.abort()\n")
    assert _probe("scratch-abort", "raptor_scratch_abort_on_import") is False
    # Still alive to assert anything at all — that IS the fix.
    assert _probe("scratch-json2", "json") is True


def test_probe_hung_import_times_out_to_false(
    scratch_import_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hung import must not hang the run: the probe child is
    bounded and the timeout reads as unavailable."""
    mod = scratch_import_path / "raptor_scratch_sleep_on_import.py"
    mod.write_text("import time\ntime.sleep(600)\n")
    monkeypatch.setattr(_availability, "_PROBE_TIMEOUT_S", 2.0)
    t0 = time.monotonic()
    assert _probe("scratch-sleep", "raptor_scratch_sleep_on_import") is False
    assert time.monotonic() - t0 < 30.0


def test_probe_memoizes_no_second_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once-per-run cache semantics: the second call for a probed
    name spawns no second child; ``clear_probe_cache`` re-arms."""
    calls: list[tuple[str, str]] = []

    def _counting_child(name: str, module: str) -> bool:
        calls.append((name, module))
        return True

    monkeypatch.setattr(
        _availability, "_import_probe_child", _counting_child,
    )
    assert _probe("scratch-cache", "json") is True
    assert _probe("scratch-cache", "json") is True
    assert len(calls) == 1
    clear_probe_cache()
    assert _probe("scratch-cache", "json") is True
    assert len(calls) == 2


def test_probe_child_module_rides_as_argv() -> None:
    """The child command interpolates nothing: fixed ``-c`` program
    text, module name as argv data, current interpreter."""
    captured: dict[str, object] = {}

    real_run = _availability.subprocess.run

    def _spy_run(cmd: list[str], **kwargs: object):
        captured["cmd"] = cmd
        return real_run(cmd, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(_availability.subprocess, "run", _spy_run)
        assert _probe("scratch-argv", "json") is True
    cmd = captured["cmd"]
    assert cmd == [
        sys.executable, "-c", _availability._CHILD_PROBE_SOURCE, "json",
    ]
    assert "json" not in _availability._CHILD_PROBE_SOURCE
