"""Dead-owner sweep for pid-keyed session scratch (conftest wiring).

The sweep MUST hang off ``pytest_configure`` gated on
``config.workerinput`` — a session fixture never executes on an xdist
controller and the PYTEST_XDIST_WORKER env var is inheritable, so
either wrong placement leaves the sweep inert in exactly the ``-n``
sessions that leak biggest (one killed session's scratch exhausted the
tmp filesystem's inode table). These tests drive the ROOT conftest's
hook path, not just the reaper primitive.
"""

from __future__ import annotations

import os
import subprocess
import types


def _root_conftest():
    import conftest
    return conftest


def _dead_pid() -> int:
    proc = subprocess.Popen(["true"])
    proc.wait(timeout=10)
    return proc.pid


def _fake_config(worker: bool):
    cfg = types.SimpleNamespace(option=types.SimpleNamespace(basetemp="x"))
    if worker:
        cfg.workerinput = {"workerid": "gw0"}
    return cfg


class TestSessionScratchSweep:
    def test_controller_configure_sweeps_dead_dirs(
            self, tmp_path, monkeypatch):
        conftest_mod = _root_conftest()
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
        dead = tmp_path / f"raptor-pytest-{_dead_pid()}-oldsess"
        dead.mkdir()
        (dead / "leak").write_text("x")
        live = tmp_path / f"raptor-pytest-{os.getpid()}-cur"
        live.mkdir()
        conftest_mod._sweep_dead_session_scratch(_fake_config(worker=False))
        assert not dead.exists()
        assert live.is_dir()

    def test_worker_configure_never_sweeps(self, tmp_path, monkeypatch):
        conftest_mod = _root_conftest()
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
        dead = tmp_path / f"raptor-pytest-{_dead_pid()}-oldsess"
        dead.mkdir()
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
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
        monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw3")
        dead = tmp_path / f"raptor-pytest-{_dead_pid()}-oldsess"
        dead.mkdir()
        conftest_mod._sweep_dead_session_scratch(_fake_config(worker=False))
        assert not dead.exists()
