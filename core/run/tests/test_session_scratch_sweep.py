"""Dead-owner sweep for pid-keyed session scratch (conftest wiring).

The sweep MUST hang off ``pytest_configure`` gated on
``config.workerinput`` — a session fixture never executes on an xdist
controller and the PYTEST_XDIST_WORKER env var is inheritable, so
either wrong placement leaves the sweep inert in exactly the ``-n``
sessions that leak biggest (one killed session's scratch exhausted the
tmp filesystem's inode table). These tests drive the ROOT conftest's
hook path, not just the reaper primitive.

Safety: every test pins ``_scratch_sweep_roots`` to a PRIVATE root —
the real sweep covers the shared /tmp, and a test that lets it loose
there is itself the collateral incident these gates exist to stop.
"""

from __future__ import annotations

import os
import subprocess
import time
import types
from pathlib import Path

import pytest

# Older than every reaper age floor (dead: 1h, unverifiable: 24h).
_OLD = time.time() - 25 * 3600


def _root_conftest():
    import conftest
    return conftest


# Captured pre-patching (the autouse fixture below replaces the module
# attribute); None on a tree that predates the seam.
_ORIG_SWEEP_ROOTS = getattr(_root_conftest(), "_scratch_sweep_roots", None)


def _dead_pid() -> int:
    proc = subprocess.Popen(["true"])
    proc.wait(timeout=10)
    return proc.pid


def _fake_config(worker: bool):
    cfg = types.SimpleNamespace(option=types.SimpleNamespace(basetemp="x"))
    if worker:
        cfg.workerinput = {"workerid": "gw0"}
    return cfg


@pytest.fixture(autouse=True)
def _pin_sweep_environment(monkeypatch, tmp_path):
    """Point the sweep at a private root and pin the root-namespace
    verdict: this session may itself run inside a pid namespace (the
    batteries do), where the real probe would rightly refuse and turn
    every behavioural assert vacuous. ``raising=False`` keeps the
    fixture harmless on a pre-probe tree."""
    conftest_mod = _root_conftest()
    # Belt and braces on BOTH trees: the seam pin covers the fixed
    # conftest; the gettempdir pin covers a pre-seam tree (red-leg
    # runs against the base) whose sweep reads gettempdir directly.
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(
        conftest_mod, "_scratch_sweep_roots", lambda: {tmp_path},
        raising=False,
    )
    import core.run.tmp_reaper as reaper_mod
    monkeypatch.setattr(
        reaper_mod, "_in_child_pid_ns", lambda: False, raising=False,
    )


class TestSessionScratchSweep:
    def test_controller_configure_sweeps_dead_dirs(self, tmp_path):
        conftest_mod = _root_conftest()
        dead = tmp_path / f"raptor-pytest-{_dead_pid()}-oldsess"
        dead.mkdir()
        (dead / "leak").write_text("x")
        os.utime(dead, (_OLD, _OLD))
        live = tmp_path / f"raptor-pytest-{os.getpid()}-cur"
        live.mkdir()
        os.utime(live, (_OLD, _OLD))
        conftest_mod._sweep_dead_session_scratch(_fake_config(worker=False))
        assert not dead.exists()
        assert live.is_dir()

    def test_young_dead_dir_survives_the_sweep(self, tmp_path):
        # The conftest path inherits the reaper's age floor: a
        # freshly-touched dir is never reaped on a dead verdict alone
        # (concurrent namespaced sessions probe ESRCH for LIVE pids).
        conftest_mod = _root_conftest()
        young = tmp_path / f"raptor-pytest-{_dead_pid()}-fresh"
        young.mkdir()
        conftest_mod._sweep_dead_session_scratch(_fake_config(worker=False))
        assert young.is_dir()

    def test_worker_configure_never_sweeps(self, tmp_path):
        conftest_mod = _root_conftest()
        dead = tmp_path / f"raptor-pytest-{_dead_pid()}-oldsess"
        dead.mkdir()
        os.utime(dead, (_OLD, _OLD))
        conftest_mod._sweep_dead_session_scratch(_fake_config(worker=True))
        assert dead.is_dir()

    def test_hook_calls_the_sweep(self):
        # Placement pin: the sweep must be reachable from
        # pytest_configure (a session FIXTURE never runs on an xdist
        # controller — the original defect this file exists to stop).
        import inspect
        conftest_mod = _root_conftest()
        src = inspect.getsource(conftest_mod.pytest_configure)
        assert "_sweep_dead_session_scratch" in src

    def test_inheritable_env_var_does_not_gate(
            self, tmp_path, monkeypatch):
        # A nested controller inside an xdist worker inherits
        # PYTEST_XDIST_WORKER; worker-ness must come from workerinput.
        conftest_mod = _root_conftest()
        monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw3")
        dead = tmp_path / f"raptor-pytest-{_dead_pid()}-oldsess"
        dead.mkdir()
        os.utime(dead, (_OLD, _OLD))
        conftest_mod._sweep_dead_session_scratch(_fake_config(worker=False))
        assert not dead.exists()

    def test_default_roots_cover_tempdir_and_shared_tmp(
            self, monkeypatch, tmp_path):
        # The seam's DEFAULT must keep covering both the session
        # TMPDIR and the shared /tmp — launcher sessions scratch in
        # their private TMPDIR, bare sessions in /tmp, and the sweep
        # exists for both leak shapes.
        if _ORIG_SWEEP_ROOTS is None:
            pytest.fail("_scratch_sweep_roots seam missing from the "
                        "root conftest")
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
        assert _ORIG_SWEEP_ROOTS() == {tmp_path, Path("/tmp")}
