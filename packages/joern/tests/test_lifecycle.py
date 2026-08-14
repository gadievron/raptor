"""Tests for the Joern server lifecycle manager."""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.joern import lifecycle


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


class TestConnectExisting(unittest.TestCase):
    def test_dead_pid_returns_none(self):
        state = {"pid": 2_000_000_000, "port": 9999}
        self.assertIsNone(lifecycle._connect_existing(state))

    def test_missing_port_returns_none(self):
        state = {"pid": os.getpid()}
        self.assertIsNone(lifecycle._connect_existing(state))

    @patch.object(lifecycle, "_pid_alive", return_value=True)
    @patch.object(lifecycle, "_health_check", return_value=True)
    def test_healthy_server_returns_client(self, _hc, _pa):
        state = {"pid": 12345, "port": 8888, "heap_mb": 4096}
        srv = lifecycle._connect_existing(state)
        self.assertIsNotNone(srv)
        self.assertEqual(srv.port, 8888)

    @patch.object(lifecycle, "_pid_alive", return_value=True)
    @patch.object(lifecycle, "_health_check", return_value=False)
    def test_unhealthy_server_returns_none(self, _hc, _pa):
        state = {"pid": 12345, "port": 8888}
        self.assertIsNone(lifecycle._connect_existing(state))


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
        srv = MagicMock()
        srv.pid = 12345
        srv.port = 8888
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
        srv = MagicMock()
        srv.pid = 12345
        srv.port = 8888
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
        srv = MagicMock()
        srv.pid = 12345
        srv.port = 8888
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

        new_srv = MagicMock()
        new_srv.pid = 99999
        new_srv.port = 7777
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
        srv = MagicMock()
        srv.pid = 12345
        srv.port = 8888
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
        srv = MagicMock()
        srv.pid = 12345
        srv.port = 8888
        mock_start.return_value = srv

        with self.assertRaises(ValueError):
            with lifecycle.joern_session():
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

        new_srv = MagicMock()
        new_srv.pid = 99999
        new_srv.port = 7777
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


if __name__ == "__main__":
    unittest.main()
