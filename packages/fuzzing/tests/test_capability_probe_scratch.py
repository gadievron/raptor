"""The sanitiser compile probe must leave no scratch behind.

The probe's source/output files AND the compiler's own intermediates
(clang derives temp object names from the source basename and parks
them in TMPDIR) all live in one context-managed dir that dies with
the probe — on success, compile failure, and timeout alike.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from packages.fuzzing import capability


from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(capability, "exec_workdir", lambda: tmp_path)
    return tmp_path


def _fake_run(record: dict, *, returncode: int = 0,
              raise_timeout: bool = False):
    def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
        env = kwargs["env"]
        record["tmpdir"] = env["TMPDIR"]
        record["cmd"] = cmd
        # Simulate the compiler stranding an intermediate object in
        # its TMPDIR (the leak shape observed with real clang).
        Path(env["TMPDIR"], "raptor-fuzz-probe-stray.o").write_bytes(b"")
        if raise_timeout:
            raise subprocess.TimeoutExpired(cmd, 30)
        return subprocess.CompletedProcess(cmd, returncode, "", "")
    return run


def test_probe_success_leaves_no_scratch(workdir: Path,
                                         monkeypatch: pytest.MonkeyPatch):
    record: dict = {}
    patch_module_attribute(monkeypatch, capability, 'subprocess', "run", _fake_run(record))
    assert capability._probe_clang_sanitiser("clang", "address") is True
    # The compiler ran with TMPDIR inside the probe's doomed dir...
    probe_dir = Path(record["tmpdir"])
    assert probe_dir.name.startswith("raptor-fuzz-probe-")
    assert probe_dir.parent == workdir
    # ...and nothing survives the probe.
    assert list(workdir.iterdir()) == []


def test_probe_compile_failure_leaves_no_scratch(
        workdir: Path, monkeypatch: pytest.MonkeyPatch):
    record: dict = {}
    patch_module_attribute(monkeypatch,
        capability, 'subprocess', "run", _fake_run(record, returncode=1),
    )
    assert capability._probe_clang_sanitiser("clang", "memory") is False
    assert list(workdir.iterdir()) == []


def test_probe_timeout_leaves_no_scratch(workdir: Path,
                                         monkeypatch: pytest.MonkeyPatch):
    record: dict = {}
    patch_module_attribute(monkeypatch,
        capability, 'subprocess', "run",
        _fake_run(record, raise_timeout=True),
    )
    assert capability._probe_clang_sanitiser("clang", "fuzzer") is False
    assert list(workdir.iterdir()) == []


def test_probe_source_matches_sanitizer_mode(workdir: Path,
                                             monkeypatch: pytest.MonkeyPatch):
    record: dict = {}
    patch_module_attribute(monkeypatch, capability, 'subprocess', "run", _fake_run(record))
    capability._probe_clang_sanitiser("clang", "fuzzer")
    cmd = record["cmd"]
    assert "-fsanitize=fuzzer" in cmd
    src = next(a for a in cmd if a.endswith(".c"))
    # Source is consumed before the dir dies, so re-read via the fake
    # is impossible — assert the path lived inside the probe dir.
    assert Path(src).parent == Path(record["tmpdir"])
