"""Bounded relaunch-on-death + stop() teardown hardening.

Replays the v4 head-to-head failure: the Joern taint server died
during the pre-sweep's stuck-query restart and stayed dead through
BOTH runs' entire review loops — every query failed fast with
``["server process exited"]`` and the taint tier could never earn
mechanical corroboration. Two defects:

1. ``stop()`` let a second ``TimeoutExpired`` (post-SIGKILL wait on a
   huge-heap JVM) escape, aborting cleanup with a dead-but-retained
   ``_proc`` and a leaked workdir.
2. ``restart()`` was reachable only from query-timeout branches; a
   dead process fails fast BEFORE any timeout, so no relaunch was
   ever attempted.

All tests are hermetic — no real Joern process is started.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.joern.server import JoernServer


def _dead_proc(pid: int = 2_000_000_000) -> MagicMock:
    proc = MagicMock()
    proc.pid = pid
    proc.poll.return_value = 137
    return proc


class TestStopSurvivesUnreapableProcess:
    def test_second_timeout_expired_does_not_escape(self, tmp_path):
        srv = JoernServer()
        proc = MagicMock()
        # Nonexistent pid: os.getpgid raises, so _signal_group falls
        # back to proc.terminate()/kill() (both mocked).
        proc.pid = 2_000_000_000
        proc.wait.side_effect = subprocess.TimeoutExpired(
            cmd="joern", timeout=5,
        )
        srv._proc = proc
        workdir = tmp_path / "raptor-joern-ws-test"
        workdir.mkdir()
        srv._workdir = str(workdir)

        # Pre-fix: the post-SIGKILL wait raised TimeoutExpired out of
        # stop(), keeping the dead _proc and leaking the workdir.
        srv.stop()

        assert srv._proc is None
        assert srv._workdir is None
        assert not workdir.exists()


class TestEnsureAlive:
    def test_live_process_is_noop(self):
        srv = JoernServer()
        proc = MagicMock()
        proc.poll.return_value = None
        srv._proc = proc
        with patch.object(srv, "restart") as restart:
            assert srv.ensure_alive() is True
        restart.assert_not_called()

    def test_dead_process_triggers_relaunch(self):
        srv = JoernServer()
        srv._proc = _dead_proc()
        with patch.object(srv, "restart", return_value=True) as restart:
            assert srv.ensure_alive() is True
        restart.assert_called_once()

    def test_cooldown_bounds_attempts(self):
        # Hermetic clock: ``time.monotonic()`` is seconds-since-boot
        # on Linux, so real-clock arithmetic here couples the test to
        # host uptime (a freshly booted CI runner sits inside the
        # first cooldown window). Drive the window explicitly.
        srv = JoernServer()
        srv._proc = _dead_proc()
        clock = {"now": 1000.0}
        with patch("packages.joern.server.time.monotonic",
                   side_effect=lambda: clock["now"]), \
                patch.object(srv, "restart", return_value=False) as restart:
            assert srv.ensure_alive() is False
            # Within the cooldown window: no second boot attempt.
            clock["now"] += 1.0
            assert srv.ensure_alive() is False
            assert restart.call_count == 1
            # Window elapsed: retry.
            clock["now"] += 400.0
            assert srv.ensure_alive() is False
            assert restart.call_count == 2

    def test_first_attempt_allowed_on_freshly_booted_host(self):
        # Regression: with the old ``0.0`` "never attempted" sentinel,
        # a host whose monotonic clock (== uptime on Linux) was still
        # below the cooldown refused the FIRST relaunch attempt — the
        # taint tier stayed down for the first five minutes after boot,
        # exactly the window CI runners live in.
        srv = JoernServer()
        srv._proc = _dead_proc()
        with patch("packages.joern.server.time.monotonic",
                   return_value=42.0), \
                patch.object(srv, "restart", return_value=True) as restart:
            assert srv.ensure_alive() is True
        restart.assert_called_once()

    def test_never_started_handle_left_alone(self):
        # A handle that never served a CPG (e.g. lifecycle reuse of a
        # process this object doesn't own) has nothing to relaunch.
        srv = JoernServer()
        with patch.object(srv, "restart") as restart:
            assert srv.ensure_alive() is False
        restart.assert_not_called()

    def test_failed_relaunch_with_proc_none_retries(self):
        # A failed restart() leaves _proc None but _cpg_path set — the
        # next cooldown window must retry rather than giving up.
        srv = JoernServer()
        srv._cpg_path = Path("/nonexistent/cpg.bin")
        with patch.object(srv, "restart", return_value=False) as restart:
            assert srv.ensure_alive() is False
            restart.assert_called_once()

    def test_noop_while_restart_in_progress(self):
        srv = JoernServer()
        srv._proc = _dead_proc()
        srv._restarting.set()
        with patch.object(srv, "restart") as restart:
            assert srv.ensure_alive() is False
        restart.assert_not_called()

    def test_death_and_degradation_are_loud(self, caplog):
        srv = JoernServer()
        srv._proc = _dead_proc()
        with patch.object(srv, "restart", return_value=False), \
                caplog.at_level("WARNING", logger="packages.joern.server"):
            srv.ensure_alive()
        messages = " ".join(r.getMessage() for r in caplog.records)
        assert "dead" in messages
        assert "relaunch" in messages
        assert "remains DOWN" in messages


class TestReusedHandleQueryability:
    def test_connect_existing_sets_restarting_event(self):
        # __new__ bypasses __init__; without _restarting every query()
        # on a reused server raised AttributeError.
        from packages.joern import lifecycle

        state = {
            "pid": 12345, "port": 8888,
            "auth_user": "raptor", "auth_password": "test-credential",
        }
        with patch.object(lifecycle, "_pid_alive", return_value=True), \
                patch.object(lifecycle, "_health_check", return_value=True):
            srv = lifecycle._connect_existing(state)
        assert srv is not None
        assert not srv._restarting.is_set()
        assert srv._relaunch_last_attempt is None
