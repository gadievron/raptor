"""Subprocess isolation of the availability probes.

The probe must never import the probed module in-process: angr's
import chain reaches pypcode_native's C++ init, which can abort the
host uncatchably (SIGABRT) — Python cannot catch a signal raised
inside a C extension's init, so an in-process probe kills the whole
run (observed as full xdist worker node-down). These tests make the
process boundary visible with a scratch module that exits nonzero.
The contained-crash test additionally imports a module that attempts
``os.abort()``: the tracer records the signal and terminates that owned
child quietly; the caller gets a clean False.
"""
from __future__ import annotations

import os
import signal
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
            "raptor_scratch_exit_on_import",
            "raptor_scratch_sleep_on_import",
        },
    )
    clear_probe_cache()
    yield
    clear_probe_cache()


@pytest.fixture()
def scratch_import_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Explicitly load trusted fixture modules AFTER safe interpreter startup.

    Production probes must ignore ambient PYTHONPATH, so test hazards are
    installed through this test-only source override rather than env.
    """
    monkeypatch.setattr(_availability, '_CHILD_PROBE_SOURCE',
        f"import sys; sys.path.insert(0, {str(tmp_path)!r}); " + _availability._CHILD_PROBE_SOURCE)
    return tmp_path


def test_probe_stdlib_module_available() -> None:
    """Success path: a stdlib module probes True."""
    assert _probe("scratch-json", "json") is True


def test_probe_nonexistent_module_unavailable() -> None:
    """Failure path: a module that does not exist probes False."""
    assert _probe("scratch-nope", "raptor_scratch_no_such_module") is False


def test_probe_child_nonzero_exit_is_unavailable(scratch_import_path: Path) -> None:
    """Default coverage proves the process boundary without a native crash."""
    mod = scratch_import_path / "raptor_scratch_exit_on_import.py"
    entered = scratch_import_path / "exit-probe-pid"
    mod.write_text(
        "import os\n"
        f"open({str(entered)!r}, 'w').write(str(os.getpid()))\n"
        "raise SystemExit(23)\n"
    )
    assert _probe("scratch-exit", "raptor_scratch_exit_on_import") is False
    assert int(entered.read_text()) != os.getpid()
    assert _probe("scratch-json-after-exit", "json") is True


def test_probe_survives_import_that_aborts_the_process(
    scratch_import_path: Path, monkeypatch, expected_crash_runner,
) -> None:
    """The registered hazard, made deterministic: a module whose
    import calls ``os.abort()``. The tracer observes SIGABRT and
    terminates the child quietly; the isolated probe maps that loss
    to False. Regression guards fail before an in-process abort.
    """
    mod = scratch_import_path / "raptor_scratch_abort_on_import.py"
    from types import SimpleNamespace
    from core.security import python_probe

    marker = Path(str(mod) + "entered")
    caller_pid = os.getpid()
    mod.write_text(
        "import os\n"
        # A regression to in-process or unwrapped import must fail quietly,
        # before the fixture deliberately aborts.
        f"assert os.getpid() != {caller_pid}, 'probe ran in caller'\n"
        f"assert os.getppid() != {caller_pid}, 'probe was not traced'\n"
        "open(__file__ + 'entered', 'w').close()\nos.abort()\n"
    )
    real_subprocess = python_probe.subprocess
    traces = []

    def contained_run(command, **options):
        if "raptor_scratch_abort_on_import" not in command:
            return real_subprocess.run(command, **options)
        assert options.pop("stdout") == real_subprocess.PIPE
        assert options.pop("stderr") == real_subprocess.PIPE
        result = expected_crash_runner(command, ready_file=marker, **options)
        traces.append(result)
        return result.process  # actual SIGKILL status, never a forged SIGABRT

    monkeypatch.setattr(python_probe, "subprocess", SimpleNamespace(
        run=contained_run, PIPE=real_subprocess.PIPE,
    ))
    assert _probe("scratch-abort", "raptor_scratch_abort_on_import") is False
    assert marker.exists(), "probe did not enter aborting module"
    assert len(traces) == 1
    assert traces[0].observed_signal == signal.SIGABRT
    assert traces[0].process.returncode == -signal.SIGKILL
    # Still alive to assert anything at all — that IS the fix.
    assert _probe("scratch-json2", "json") is True


def test_probe_hung_import_times_out_to_false(
    scratch_import_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hung import must not hang the run: the probe child is
    bounded and the timeout reads as unavailable."""
    mod = scratch_import_path / "raptor_scratch_sleep_on_import.py"
    mod.write_text("import time\nopen(__file__ + 'entered', 'w').close()\ntime.sleep(600)\n")
    monkeypatch.setattr(_availability, "_PROBE_TIMEOUT_S", 2.0)
    t0 = time.monotonic()
    assert _probe("scratch-sleep", "raptor_scratch_sleep_on_import") is False
    assert time.monotonic() - t0 < 30.0
    assert Path(str(mod)+"entered").exists(), "probe did not enter hanging module"


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
        assert kwargs["cwd"] == os.sep
        return real_run(cmd, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(_availability.subprocess, "run", _spy_run)
        assert _probe("scratch-argv", "json") is True
    cmd = captured["cmd"]
    assert cmd == [
        sys.executable, "-E", "-c", _availability._CHILD_PROBE_SOURCE, "json",
        _availability.site.getusersitepackages(),
    ]
    assert "json" not in _availability._CHILD_PROBE_SOURCE


def test_probe_ignores_target_module_and_pythonpath(tmp_path, monkeypatch):
    marker = tmp_path/'executed'
    (tmp_path/'z3.py').write_text(
        f'from pathlib import Path\nPath({str(marker)!r}).write_text("bad")\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('PYTHONPATH', str(tmp_path))
    _availability._import_probe_child('z3', 'z3')
    assert not marker.exists()
