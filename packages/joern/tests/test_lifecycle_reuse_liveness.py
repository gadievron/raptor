"""Lifecycle-reused handles, restart bookkeeping, and group kills.

Three defects pinned here:

1. ``ensure_alive`` judged liveness only by ``Popen.poll()``: a
   lifecycle-reused handle has ``_proc=None`` forever, so a HEALTHY
   shared server was judged dead on the first orchestrator tick after
   ``import_cpg`` and a duplicate multi-GB JVM was booted beside it.
2. ``restart()`` with a vanished cpg.bin returned True — a
   fabricated-healthy wedge (``_cpg_loaded`` stayed False, every
   query said "no CPG loaded", ``ensure_alive`` kept saying fine).
   And the restarted JVM's new pid/port/credential never reached the
   lifecycle state file, so ``joern_release`` could not stop it.
3. ``_kill_server`` signalled the pid, not the process group, despite
   ``start_new_session=True`` — wrapper-spawned JVMs were orphaned.

All hermetic — no real Joern process.
"""

from __future__ import annotations

import json
import signal
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.joern import lifecycle
from packages.joern.server import JoernServer


class _StateDirFixture:
    def setup_method(self, _method):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        d = Path(self._tmp.name)
        self._orig = (lifecycle._STATE_DIR, lifecycle._STATE_FILE,
                      lifecycle._LOCK_FILE)
        lifecycle._STATE_DIR = d
        lifecycle._STATE_FILE = d / "joern-server.json"
        lifecycle._LOCK_FILE = d / "joern-server.lock"

    def teardown_method(self, _method):
        (lifecycle._STATE_DIR, lifecycle._STATE_FILE,
         lifecycle._LOCK_FILE) = self._orig
        self._tmp.cleanup()

    @staticmethod
    def _seed(state):
        lifecycle._STATE_FILE.write_text(json.dumps(state))

    @staticmethod
    def _read():
        return json.loads(lifecycle._STATE_FILE.read_text())


def _reused_handle(cpg: Path | None = None) -> JoernServer:
    """A lifecycle-reuse-shaped handle: no owned process, live URL."""
    srv = JoernServer()
    srv._proc = None
    srv._port = 8899
    srv._base_url = "http://127.0.0.1:8899"
    srv._auth_user = "raptor"
    srv._auth_password = "cred"
    if cpg is not None:
        srv._cpg_path = cpg
        srv._cpg_loaded = True
    return srv


class TestReusedHandleLiveness:
    def test_healthy_endpoint_means_alive_no_relaunch(self, tmp_path):
        """The core duplicate-JVM regression: a reused handle whose
        shared server answers must NOT be relaunched."""
        srv = _reused_handle(cpg=tmp_path / "cpg.bin")
        with patch.object(srv, "health_check", return_value=True), \
                patch.object(srv, "restart") as restart:
            assert srv.ensure_alive() is True
        restart.assert_not_called()

    def test_dead_endpoint_with_cpg_relaunches(self, tmp_path):
        srv = _reused_handle(cpg=tmp_path / "cpg.bin")
        with patch.object(srv, "health_check", return_value=False), \
                patch.object(srv, "restart", return_value=True) as restart:
            assert srv.ensure_alive() is True
        restart.assert_called_once()

    def test_dead_endpoint_never_served_cpg_left_alone(self):
        srv = _reused_handle(cpg=None)
        with patch.object(srv, "health_check", return_value=False), \
                patch.object(srv, "restart") as restart:
            assert srv.ensure_alive() is False
        restart.assert_not_called()

    def test_health_check_false_without_endpoint(self):
        srv = JoernServer()
        assert srv.health_check() is False


class TestRestartVanishedCpg:
    def test_restart_with_vanished_cpg_reports_failure(self, tmp_path):
        srv = JoernServer()
        srv._cpg_path = tmp_path / "gone" / "cpg.bin"  # does not exist
        with patch.object(srv, "stop"), \
                patch.object(srv, "start"), \
                patch.object(srv, "import_cpg") as imp:
            assert srv.restart() is False
        imp.assert_not_called()

    def test_restart_with_present_cpg_reloads(self, tmp_path):
        cpg = tmp_path / "cpg.bin"
        cpg.write_bytes(b"x")
        srv = JoernServer()
        srv._cpg_path = cpg
        with patch.object(srv, "stop"), \
                patch.object(srv, "start"), \
                patch.object(srv, "import_cpg", return_value=True) as imp:
            assert srv.restart() is True
        imp.assert_called_once()


class TestNoteServerReplaced(_StateDirFixture):
    def _srv(self, pid=4242, port=9001):
        srv = MagicMock()
        srv.pid = pid
        srv.port = port
        srv._auth_user = "raptor"
        srv._auth_password = "new-cred"
        return srv

    def test_tracked_server_state_follows_restart(self):
        self._seed({"pid": 111, "port": 8800, "refcount": 2,
                    "auth_user": "raptor", "auth_password": "old-cred",
                    "started_at": 1.0})
        with patch.object(lifecycle, "_read_comm", return_value="java"):
            lifecycle.note_server_replaced(
                old_pid=111, old_port=8800, srv=self._srv())
        state = self._read()
        assert state["pid"] == 4242
        assert state["port"] == 9001
        assert state["auth_password"] == "new-cred"
        assert state["refcount"] == 2  # refcount preserved

    def test_matches_on_port_when_old_pid_unknown(self):
        """A lifecycle-reused handle never knew the old pid — the
        port match must still update the state (the exact
        duplicate-JVM-unreleasable case)."""
        self._seed({"pid": 111, "port": 8800, "refcount": 1,
                    "auth_user": "raptor", "auth_password": "old-cred"})
        with patch.object(lifecycle, "_read_comm", return_value="java"):
            lifecycle.note_server_replaced(
                old_pid=None, old_port=8800, srv=self._srv())
        assert self._read()["pid"] == 4242

    def test_foreign_state_untouched(self):
        self._seed({"pid": 999, "port": 7000, "refcount": 1,
                    "auth_user": "raptor", "auth_password": "other"})
        lifecycle.note_server_replaced(
            old_pid=111, old_port=8800, srv=self._srv())
        state = self._read()
        assert state["pid"] == 999
        assert state["auth_password"] == "other"

    def test_no_state_file_is_noop(self):
        lifecycle.note_server_replaced(
            old_pid=111, old_port=8800, srv=self._srv())
        assert not lifecycle._STATE_FILE.exists()

    def test_restart_calls_note_server_replaced(self, tmp_path):
        cpg = tmp_path / "cpg.bin"
        cpg.write_bytes(b"x")
        srv = JoernServer()
        srv._cpg_path = cpg
        proc = MagicMock()
        proc.pid = 111
        srv._proc = proc
        srv._port = 8800
        with patch.object(srv, "stop"), \
                patch.object(srv, "start"), \
                patch.object(srv, "import_cpg", return_value=True), \
                patch.object(lifecycle, "note_server_replaced") as note:
            assert srv.restart() is True
        note.assert_called_once_with(old_pid=111, old_port=8800, srv=srv)


class TestKillServerSignalsGroup(_StateDirFixture):
    def test_group_leader_gets_killpg(self):
        state = {"pid": 5555, "comm": "java"}
        calls = []
        with patch.object(lifecycle, "_pid_is_our_server",
                          return_value=True), \
                patch.object(lifecycle, "_pid_alive",
                             return_value=False), \
                patch.object(lifecycle.os, "getpgid",
                             return_value=5555), \
                patch.object(lifecycle.os, "killpg",
                             side_effect=lambda pid, sig:
                             calls.append(("killpg", pid, sig))), \
                patch.object(lifecycle.os, "kill",
                             side_effect=lambda pid, sig:
                             calls.append(("kill", pid, sig))):
            lifecycle._kill_server(state)
        assert ("killpg", 5555, signal.SIGTERM) in calls
        assert ("kill", 5555, signal.SIGTERM) not in calls

    def test_non_leader_falls_back_to_kill(self):
        state = {"pid": 5555, "comm": "java"}
        calls = []
        with patch.object(lifecycle, "_pid_is_our_server",
                          return_value=True), \
                patch.object(lifecycle, "_pid_alive",
                             return_value=False), \
                patch.object(lifecycle.os, "getpgid",
                             return_value=1), \
                patch.object(lifecycle.os, "killpg",
                             side_effect=lambda pid, sig:
                             calls.append(("killpg", pid, sig))), \
                patch.object(lifecycle.os, "kill",
                             side_effect=lambda pid, sig:
                             calls.append(("kill", pid, sig))):
            lifecycle._kill_server(state)
        assert ("kill", 5555, signal.SIGTERM) in calls
        assert ("killpg", 5555, signal.SIGTERM) not in calls
