"""Tests for the Joern server lifecycle manager."""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.joern import lifecycle


def _mock_server(pid=12345, port=8888, uds_path=None):
    """MagicMock server with the attributes joern_acquire persists."""
    srv = MagicMock()
    srv.pid = pid
    srv.port = port
    srv._auth_user = "raptor"
    srv._auth_password = "test-credential"
    srv._uds_path = uds_path
    return srv


class _TmpState:
    """Redirect lifecycle state files to a temp directory for test isolation."""

    def __init__(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._dir = Path(self._tmpdir.name)
        self._orig_state_dir = lifecycle._STATE_DIR
        self._orig_state_file = lifecycle._STATE_FILE
        self._orig_lock_file = lifecycle._LOCK_FILE

    def install(self):
        lifecycle._STATE_DIR = self._dir
        lifecycle._STATE_FILE = self._dir / "joern-server.json"
        lifecycle._LOCK_FILE = self._dir / "joern-server.lock"

    def cleanup(self):
        lifecycle._STATE_DIR = self._orig_state_dir
        lifecycle._STATE_FILE = self._orig_state_file
        lifecycle._LOCK_FILE = self._orig_lock_file
        self._tmpdir.cleanup()

    @property
    def state_file(self):
        return lifecycle._STATE_FILE


class TestPidAlive(unittest.TestCase):
    def test_own_pid_alive(self):
        self.assertTrue(lifecycle._pid_alive(os.getpid()))

    def test_dead_pid(self):
        self.assertFalse(lifecycle._pid_alive(2_000_000_000))


class TestStateReadWrite(unittest.TestCase):
    def setUp(self):
        self._ts = _TmpState()
        self._ts.install()

    def tearDown(self):
        self._ts.cleanup()

    def test_read_missing_returns_none(self):
        with lifecycle._locked() as fd:
            self.assertIsNone(lifecycle._read_state(fd))

    def test_write_then_read(self):
        state = {"pid": 123, "port": 9999, "refcount": 1}
        with lifecycle._locked() as fd:
            lifecycle._write_state(fd, state)
        with lifecycle._locked() as fd:
            loaded = lifecycle._read_state(fd)
        self.assertEqual(loaded["pid"], 123)
        self.assertEqual(loaded["port"], 9999)

    def test_remove_state(self):
        state = {"pid": 123, "port": 9999, "refcount": 1}
        with lifecycle._locked() as fd:
            lifecycle._write_state(fd, state)
            lifecycle._remove_state(fd)
        with lifecycle._locked() as fd:
            self.assertIsNone(lifecycle._read_state(fd))

    def test_corrupt_state_returns_none(self):
        self._ts.state_file.write_text("not json", encoding="utf-8")
        with lifecycle._locked() as fd:
            self.assertIsNone(lifecycle._read_state(fd))


_AUTH_STATE = {"auth_user": "raptor", "auth_password": "test-credential"}


class TestConnectExisting(unittest.TestCase):
    def test_dead_pid_returns_none(self):
        state = {"pid": 2_000_000_000, "port": 9999, **_AUTH_STATE}
        self.assertIsNone(lifecycle._connect_existing(state))

    def test_missing_port_returns_none(self):
        state = {"pid": os.getpid(), **_AUTH_STATE}
        self.assertIsNone(lifecycle._connect_existing(state))

    @patch.object(lifecycle, "_pid_alive", return_value=True)
    @patch.object(lifecycle, "_health_check", return_value=True)
    def test_healthy_server_returns_client(self, _hc, _pa):
        state = {"pid": 12345, "port": 8888, "heap_mb": 4096, **_AUTH_STATE}
        srv = lifecycle._connect_existing(state)
        self.assertIsNotNone(srv)
        self.assertEqual(srv.port, 8888)

    @patch.object(lifecycle, "_pid_alive", return_value=True)
    def test_socket_gone_returns_none(self, _pa):
        """A strong-tier server whose unix socket vanished is
        unreachable regardless of process liveness — recycle."""
        state = {"pid": 12345, "port": 8888,
                 "socket_path": "/nonexistent/raptor/joern.sock",
                 **_AUTH_STATE}
        self.assertIsNone(lifecycle._connect_existing(state))

    @patch.object(lifecycle, "_pid_alive", return_value=True)
    def test_socket_path_carried_into_handle_and_health_check(self, _pa):
        with tempfile.TemporaryDirectory() as d:
            sock = os.path.join(d, "joern.sock")
            Path(sock).touch()
            state = {"pid": 12345, "port": 8888, "socket_path": sock,
                     **_AUTH_STATE}
            with patch.object(lifecycle, "_health_check",
                              return_value=True) as hc:
                srv = lifecycle._connect_existing(state)
            self.assertIsNotNone(srv)
            self.assertEqual(srv._uds_path, sock)
            self.assertIsNone(srv._uds_dir)  # reuse handles never own it
            self.assertEqual(hc.call_args[0][2], sock)

    @patch.object(lifecycle, "_pid_alive", return_value=True)
    @patch.object(lifecycle, "_health_check", return_value=False)
    def test_unhealthy_server_returns_none(self, _hc, _pa):
        state = {"pid": 12345, "port": 8888, **_AUTH_STATE}
        self.assertIsNone(lifecycle._connect_existing(state))

    @patch.object(lifecycle, "_pid_alive", return_value=True)
    @patch.object(lifecycle, "_health_check", return_value=True)
    def test_missing_auth_credential_returns_none(self, _hc, _pa):
        # State written before server auth existed — the running
        # server is unauthenticated and must be recycled, not reused.
        state = {"pid": 12345, "port": 8888}
        self.assertIsNone(lifecycle._connect_existing(state))

    @patch.object(lifecycle, "_pid_alive", return_value=True)
    @patch.object(lifecycle, "_health_check", return_value=True)
    def test_reuse_handle_carries_every_init_field(self, _hc, _pa):
        """The reuse handle is built through __init__ (connect_existing),
        never __new__ + field copy: every field __init__ sets — present
        AND future — must exist on it. The field-copy approach drifted
        twice (_restarting, then _flow_semantics/_last_import_timeout),
        each omission an AttributeError on some method of a reused
        server (e.g. run_tiered_sweep reading _flow_semantics)."""
        from packages.joern.server import JoernServer
        state = {"pid": 12345, "port": 8888, "heap_mb": 4096,
                 "query_timeout_s": 300, **_AUTH_STATE}
        srv = lifecycle._connect_existing(state)
        self.assertIsNotNone(srv)
        reference = JoernServer()
        missing = set(vars(reference)) - set(vars(srv))
        self.assertEqual(missing, set())
        # The two historically-omitted fields, pinned explicitly.
        self.assertEqual(srv._flow_semantics, [])
        self.assertIsNone(srv._last_import_timeout)
        # Reuse handles never own the process or the socket dir.
        self.assertIsNone(srv._proc)
        self.assertIsNone(srv._uds_dir)

    @patch.object(lifecycle, "_pid_alive", return_value=True)
    def test_reconnect_carries_credential_into_health_check(self, _pa):
        state = {"pid": 12345, "port": 8888, **_AUTH_STATE}
        with patch.object(lifecycle, "_health_check",
                          return_value=True) as mock_hc:
            srv = lifecycle._connect_existing(state)
        self.assertIsNotNone(srv)
        self.assertEqual(srv._auth_user, "raptor")
        self.assertEqual(srv._auth_password, "test-credential")
        headers = mock_hc.call_args[0][1]
        self.assertIn("Authorization", headers)
        self.assertTrue(headers["Authorization"].startswith("Basic "))


class TestAcquireRelease(unittest.TestCase):
    def setUp(self):
        self._ts = _TmpState()
        self._ts.install()

    def tearDown(self):
        self._ts.cleanup()

    @patch.object(lifecycle, "_start_fresh", return_value=None)
    def test_acquire_returns_none_when_start_fails(self, _sf):
        result = lifecycle.joern_acquire()
        self.assertIsNone(result)

    @patch.object(lifecycle, "_start_fresh")
    def test_acquire_starts_fresh_and_writes_state(self, mock_start):
        srv = _mock_server()
        mock_start.return_value = srv

        result = lifecycle.joern_acquire()
        self.assertIs(result, srv)

        with lifecycle._locked() as fd:
            state = lifecycle._read_state(fd)
        self.assertEqual(state["pid"], 12345)
        self.assertEqual(state["port"], 8888)
        self.assertEqual(state["refcount"], 1)

    @patch.object(lifecycle, "_start_fresh")
    def test_release_decrements_refcount(self, mock_start):
        srv = _mock_server()
        mock_start.return_value = srv

        lifecycle.joern_acquire()

        # Manually set refcount to 2 to test decrement without stop
        with lifecycle._locked() as fd:
            state = lifecycle._read_state(fd)
            state["refcount"] = 2
            lifecycle._write_state(fd, state)

        lifecycle.joern_release()

        with lifecycle._locked() as fd:
            state = lifecycle._read_state(fd)
        self.assertIsNotNone(state)
        self.assertEqual(state["refcount"], 1)

    @patch.object(lifecycle, "_kill_server")
    @patch.object(lifecycle, "_start_fresh")
    def test_release_stops_server_at_zero(self, mock_start, mock_kill):
        srv = _mock_server()
        mock_start.return_value = srv

        lifecycle.joern_acquire()
        lifecycle.joern_release()

        mock_kill.assert_called_once()
        with lifecycle._locked() as fd:
            self.assertIsNone(lifecycle._read_state(fd))

    @patch.object(lifecycle, "_connect_existing")
    @patch.object(lifecycle, "_start_fresh")
    def test_acquire_reuses_existing(self, mock_start, mock_connect):
        # Pre-populate state
        state = {
            "pid": 12345, "port": 8888, "heap_mb": None,
            "refcount": 1, "started_at": time.time(),
            "query_timeout_s": 300,
        }
        with lifecycle._locked() as fd:
            lifecycle._write_state(fd, state)

        reused_srv = MagicMock()
        reused_srv.port = 8888
        mock_connect.return_value = reused_srv

        result = lifecycle.joern_acquire()
        self.assertIs(result, reused_srv)
        mock_start.assert_not_called()

        with lifecycle._locked() as fd:
            state = lifecycle._read_state(fd)
        self.assertEqual(state["refcount"], 2)

    @patch.object(lifecycle, "_connect_existing", return_value=None)
    @patch.object(lifecycle, "_kill_server")
    @patch.object(lifecycle, "_start_fresh")
    def test_acquire_restarts_on_dead_server(self, mock_start, mock_kill, _ce):
        state = {
            "pid": 12345, "port": 8888,
            "refcount": 1, "started_at": time.time(),
        }
        with lifecycle._locked() as fd:
            lifecycle._write_state(fd, state)

        new_srv = _mock_server(pid=99999, port=7777)
        mock_start.return_value = new_srv

        result = lifecycle.joern_acquire()
        self.assertIs(result, new_srv)
        mock_kill.assert_called_once()


class TestCleanup(unittest.TestCase):
    def setUp(self):
        self._ts = _TmpState()
        self._ts.install()

    def tearDown(self):
        self._ts.cleanup()

    def test_cleanup_removes_stale_state(self):
        state = {"pid": 2_000_000_000, "port": 9999, "refcount": 1}
        with lifecycle._locked() as fd:
            lifecycle._write_state(fd, state)

        lifecycle.joern_cleanup()

        with lifecycle._locked() as fd:
            self.assertIsNone(lifecycle._read_state(fd))

    @patch.object(lifecycle, "_pid_alive", return_value=True)
    def test_cleanup_preserves_live_state(self, _pa):
        state = {"pid": os.getpid(), "port": 9999, "refcount": 1}
        with lifecycle._locked() as fd:
            lifecycle._write_state(fd, state)

        lifecycle.joern_cleanup()

        with lifecycle._locked() as fd:
            self.assertIsNotNone(lifecycle._read_state(fd))


class TestContextManager(unittest.TestCase):
    def setUp(self):
        self._ts = _TmpState()
        self._ts.install()

    def tearDown(self):
        self._ts.cleanup()

    @patch.object(lifecycle, "_start_fresh", return_value=None)
    def test_session_yields_none_on_failure(self, _sf):
        with lifecycle.joern_session() as srv:
            self.assertIsNone(srv)

    @patch.object(lifecycle, "_kill_server")
    @patch.object(lifecycle, "_start_fresh")
    def test_session_releases_on_exit(self, mock_start, mock_kill):
        srv = _mock_server()
        mock_start.return_value = srv

        with lifecycle.joern_session() as s:
            self.assertIs(s, srv)
            with lifecycle._locked() as fd:
                state = lifecycle._read_state(fd)
            self.assertEqual(state["refcount"], 1)

        mock_kill.assert_called_once()
        with lifecycle._locked() as fd:
            self.assertIsNone(lifecycle._read_state(fd))

    @patch.object(lifecycle, "_kill_server")
    @patch.object(lifecycle, "_start_fresh")
    def test_session_releases_on_exception(self, mock_start, mock_kill):
        srv = _mock_server()
        mock_start.return_value = srv

        with self.assertRaises(ValueError), lifecycle.joern_session():
            raise ValueError("boom")

        mock_kill.assert_called_once()


class TestStaleRecycle(unittest.TestCase):
    def setUp(self):
        self._ts = _TmpState()
        self._ts.install()

    def tearDown(self):
        self._ts.cleanup()

    @patch.object(lifecycle, "_kill_server")
    @patch.object(lifecycle, "_start_fresh")
    def test_stale_server_recycled(self, mock_start, mock_kill):
        state = {
            "pid": os.getpid(), "port": 8888,
            "refcount": 1,
            "started_at": time.time() - lifecycle._STALE_THRESHOLD_S - 100,
        }
        with lifecycle._locked() as fd:
            lifecycle._write_state(fd, state)

        new_srv = _mock_server(pid=99999, port=7777)
        mock_start.return_value = new_srv

        result = lifecycle.joern_acquire()
        self.assertIs(result, new_srv)
        mock_kill.assert_called_once()


class TestHeapMismatchWarning(unittest.TestCase):
    def setUp(self):
        self._ts = _TmpState()
        self._ts.install()

    def tearDown(self):
        self._ts.cleanup()

    @patch.object(lifecycle, "_connect_existing")
    def test_heap_mismatch_logs_warning(self, mock_connect):
        state = {
            "pid": 12345, "port": 8888, "heap_mb": 2048,
            "refcount": 1, "started_at": time.time(),
            "query_timeout_s": 300,
        }
        with lifecycle._locked() as fd:
            lifecycle._write_state(fd, state)

        srv = MagicMock()
        srv.port = 8888
        mock_connect.return_value = srv

        from packages.joern.tunables import JoernTunables
        tunables = JoernTunables(heap_mb=8192)

        with self.assertLogs("packages.joern.lifecycle", level="WARNING") as cm:
            lifecycle.joern_acquire(tunables)

        self.assertTrue(any("8192" in msg and "2048" in msg for msg in cm.output))


class TestStateFilePermissions(unittest.TestCase):
    def setUp(self):
        self._ts = _TmpState()
        self._ts.install()

    def tearDown(self):
        self._ts.cleanup()

    def test_write_state_creates_file_with_0600(self):
        state = {"pid": 123, "port": 9999, "refcount": 1, **_AUTH_STATE}
        with lifecycle._locked() as fd:
            lifecycle._write_state(fd, state)
        mode = self._ts.state_file.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_rewrite_over_loose_tmp_stays_0600(self):
        # A leftover .tmp with loose permissions must not leak through
        # the rename.
        tmp = self._ts.state_file.with_suffix(".tmp")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text("{}", encoding="utf-8")
        os.chmod(tmp, 0o644)
        state = {"pid": 123, "port": 9999, "refcount": 1, **_AUTH_STATE}
        with lifecycle._locked() as fd:
            lifecycle._write_state(fd, state)
        mode = self._ts.state_file.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_read_state_tightens_legacy_permissions(self):
        self._ts.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._ts.state_file.write_text('{"pid": 1}', encoding="utf-8")
        os.chmod(self._ts.state_file, 0o644)
        with lifecycle._locked() as fd:
            loaded = lifecycle._read_state(fd)
        self.assertEqual(loaded["pid"], 1)
        mode = self._ts.state_file.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


class TestAuthCredentialPersistence(unittest.TestCase):
    def setUp(self):
        self._ts = _TmpState()
        self._ts.install()

    def tearDown(self):
        self._ts.cleanup()

    @patch.object(lifecycle, "_start_fresh")
    def test_acquire_persists_credential(self, mock_start):
        srv = _mock_server()
        mock_start.return_value = srv

        lifecycle.joern_acquire()

        with lifecycle._locked() as fd:
            state = lifecycle._read_state(fd)
        self.assertEqual(state["auth_user"], "raptor")
        self.assertEqual(state["auth_password"], "test-credential")
        mode = self._ts.state_file.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    @patch.object(lifecycle, "_start_fresh")
    def test_acquire_persists_socket_path(self, mock_start):
        """Strong-tier servers are reachable only via their unix
        socket — the state file must carry it or reuse is impossible."""
        mock_start.return_value = _mock_server(
            uds_path="/tmp/raptor-joern-uds-x/joern.sock")

        lifecycle.joern_acquire()

        with lifecycle._locked() as fd:
            state = lifecycle._read_state(fd)
        self.assertEqual(state["socket_path"],
                         "/tmp/raptor-joern-uds-x/joern.sock")

    def test_kill_server_removes_socket_dir(self):
        """A group SIGKILL skips the supervisor's own unlink — the
        killer must reap the socket dir from the state's path."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "raptor-joern-uds-abc123"
            d.mkdir()
            (d / "joern.sock").touch()
            state = {"pid": 12345, "socket_path": str(d / "joern.sock")}
            with patch.object(lifecycle, "_pid_is_our_server",
                              return_value=True), \
                    patch.object(lifecycle, "_pid_alive",
                                 return_value=False), \
                    patch.object(lifecycle, "_signal_server"):
                lifecycle._kill_server(state)
            self.assertFalse(d.exists())

    def test_socket_dir_reaper_is_prefix_gated(self):
        """A corrupt state file must never aim the rmtree at an
        arbitrary directory."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "important-data"
            d.mkdir()
            (d / "joern.sock").touch()
            lifecycle._remove_socket_dir(
                {"socket_path": str(d / "joern.sock")})
            self.assertTrue(d.exists())

    def test_acquire_returns_none_when_auth_unsupported(self):
        # start() raises when the launcher lacks --server-auth-* —
        # the lifecycle must surface None (subprocess-per-query
        # fallback) rather than an unauthenticated server.
        from packages.joern.server import JoernServer

        with patch.object(
            JoernServer, "start",
            side_effect=RuntimeError("joern launcher lacks --server-auth-*"),
        ):
            result = lifecycle.joern_acquire()
        self.assertIsNone(result)
        with lifecycle._locked() as fd:
            self.assertIsNone(lifecycle._read_state(fd))


if __name__ == "__main__":
    unittest.main()
