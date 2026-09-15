"""Group-kill escalation for Joern server stop/restart.

The stop ladder's waits observe only the process-group LEADER — on
the strong tier that is the netns forwarder, not the JVM. A member
can outlive it (dead-first wrapper reaps instantly and skips the
SIGKILL branch; the JVM catches SIGTERM and wedges in its shutdown
hook behind the stuck query), and each stuck-query restart then
leaked one multi-GB JVM. stop() now verifies the whole group is dead
before teardown, escalating TERM → bounded wait → SIGKILL; restart()
reaps the old group before booting the replacement; the lifecycle
kill applies the same group-aware rule.

Hermetic — no real JVM. Stand-ins are python children: a
SIGTERM-ignoring member plays the wedged JVM, an exiting leader plays
the dead-first wrapper.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from packages.joern import lifecycle
from packages.joern import server as server_mod
from packages.joern.server import (
    JoernServer,
    _ensure_group_dead,
    _pgid_alive,
)

# Process-group semantics and the zombie-aware liveness probe are
# exercised against real children and procfs.
pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="process-group escalation is verified via procfs",
)

# A member that plays the wedged JVM: ignores SIGTERM, only SIGKILL
# ends it.
_IGNORING_MEMBER_SRC = (
    "import signal, time, sys;"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
    "print('ready', flush=True);"
    "time.sleep(300)"
)

# A leader that plays the dead-first wrapper: spawns the ignoring
# member into its own (inherited) process group, reports the member
# pid, then exits — leaving the member the only survivor of the group.
_DYING_LEADER_SRC = (
    "import subprocess, sys;"
    "child = subprocess.Popen([sys.executable, '-c', sys.argv[1]],"
    " stdout=subprocess.PIPE, text=True);"
    "child.stdout.readline();"
    "print(child.pid, flush=True)"
)


def _pid_gone(pid: int) -> bool:
    """True when *pid* no longer exists (a reparented-and-reaped kill
    victim) or is a zombie (killed, awaiting reap by its reaper)."""
    try:
        stat = open(f"/proc/{pid}/stat").read()
    except OSError:
        return True
    # Field 3 (after the parenthesised comm) is the state.
    return stat.rsplit(")", 1)[-1].split()[0] == "Z"


def _wait_gone(pid: int, timeout_s: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _pid_gone(pid):
            return True
        time.sleep(0.05)
    return False


@pytest.fixture(autouse=True)
def _short_graces(monkeypatch):
    """Bound the escalation waits so tests stay fast."""
    monkeypatch.setattr(server_mod, "_GROUP_KILL_GRACE_S", 0.5)
    monkeypatch.setattr(server_mod, "_SHUTDOWN_GRACE_S", 1.0)


@pytest.fixture
def _reap_all():
    """Kill every group this test spawned, pass or fail."""
    pgids: list[int] = []
    yield pgids
    for pgid in pgids:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass


def _spawn_dead_leader_with_survivor(pgids: list[int]) -> tuple:
    """(exited leader Popen, surviving SIGTERM-ignoring member pid)."""
    leader = subprocess.Popen(
        [sys.executable, "-c", _DYING_LEADER_SRC, _IGNORING_MEMBER_SRC],
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    pgids.append(leader.pid)
    assert leader.stdout is not None
    member_pid = int(leader.stdout.readline())
    leader.wait(timeout=30)
    assert not _pid_gone(member_pid), "member must survive its leader"
    return leader, member_pid


def _server_with(proc, pgid) -> JoernServer:
    srv = JoernServer()
    srv._proc = proc
    srv._pgid = pgid
    return srv


class TestEnsureGroupDead:
    def test_escalates_past_sigterm_immunity(self, _reap_all):
        proc = subprocess.Popen(
            [sys.executable, "-c", _IGNORING_MEMBER_SRC],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        _reap_all.append(proc.pid)
        assert proc.stdout is not None
        proc.stdout.readline()
        assert _pgid_alive(proc.pid)
        assert _ensure_group_dead(proc.pid, label="test")
        proc.wait(timeout=10)
        assert not _pgid_alive(proc.pid)

    def test_never_signals_own_group(self):
        assert _ensure_group_dead(os.getpgrp(), label="test") is False

    def test_empty_and_absent_groups_are_trivially_dead(self):
        assert _ensure_group_dead(None, label="test")
        assert _ensure_group_dead(2_000_000_000, label="test")

    def test_non_int_pgid_is_a_clean_no_op(self, monkeypatch):
        """Handle- and state-file-sourced pgids are not statically
        guaranteed to be ints (a mocked Popen's ``.pid``, a corrupt
        state record) — the guard must refuse the shape without
        signalling anything or raising."""
        from unittest.mock import Mock

        signalled: list[tuple] = []
        monkeypatch.setattr(
            server_mod.os, "killpg",
            lambda *args: signalled.append(args),
        )
        for bad in (Mock(), "5555", 5555.0, True):
            assert _ensure_group_dead(bad, label="test") is True
        assert signalled == []


class TestStopKillsSurvivingMembers:
    def test_dead_leader_surviving_member_is_killed(self, _reap_all):
        """The leaked-JVM shape: the wrapper died first, so the stop
        ladder's wait() reaps instantly and never escalates — the
        group verification must kill the member anyway."""
        leader, member_pid = _spawn_dead_leader_with_survivor(_reap_all)
        srv = _server_with(leader, leader.pid)
        srv.stop()
        assert _wait_gone(member_pid), (
            "SIGTERM-immune group member survived stop()"
        )
        assert srv._proc is None
        assert srv._pgid is None

    def test_sigterm_immune_leader_is_killed(self, _reap_all):
        proc = subprocess.Popen(
            [sys.executable, "-c", _IGNORING_MEMBER_SRC],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        _reap_all.append(proc.pid)
        assert proc.stdout is not None
        proc.stdout.readline()
        srv = _server_with(proc, proc.pid)
        srv.stop()
        assert _wait_gone(proc.pid)


class TestRestartReapsBeforeReplacing:
    def test_restart_verifies_old_group_dead_before_start(
        self, _reap_all, monkeypatch,
    ):
        leader, member_pid = _spawn_dead_leader_with_survivor(_reap_all)
        srv = _server_with(leader, leader.pid)
        member_alive_at_start: list[bool] = []
        monkeypatch.setattr(
            srv, "start",
            lambda: member_alive_at_start.append(not _pid_gone(member_pid)),
        )
        assert srv.restart() is True
        assert member_alive_at_start == [False], (
            "restart() must reap the old server's group BEFORE "
            "booting the replacement"
        )

    def test_restart_reverifies_after_stop_as_second_grace_window(
        self, _reap_all, monkeypatch,
    ):
        """restart()'s own _ensure_group_dead is a deliberate SECOND
        grace window on top of stop()'s: it only matters when stop()'s
        escalation timed out (SIGKILLed JVM still in kernel teardown —
        stop() rightly does not block cleanup on that, but the caller
        about to boot a replacement must). Pin the call sequence so
        removing the restart-side re-verification fails here."""
        leader, _member_pid = _spawn_dead_leader_with_survivor(_reap_all)
        old_pgid = leader.pid
        srv = _server_with(leader, old_pgid)
        calls: list[tuple] = []
        real = server_mod._ensure_group_dead

        def _recording(pgid, *, label="", grace_s=None):
            calls.append((pgid, label))
            return real(pgid, label=label, grace_s=grace_s)

        monkeypatch.setattr(server_mod, "_ensure_group_dead", _recording)
        monkeypatch.setattr(srv, "start", lambda: None)
        assert srv.restart() is True
        assert [pgid for pgid, _ in calls] == [old_pgid, old_pgid], (
            "restart must verify the old group twice: once inside "
            "stop(), once as its own pre-boot re-check"
        )
        assert "restart" in calls[1][1]

    def test_reused_handle_restart_kills_via_lifecycle_state(
        self, monkeypatch,
    ):
        """connect_existing handles own no Popen: stop() has nothing
        to signal, so restart must address the recorded server
        through the lifecycle state file."""
        calls: list[dict] = []
        monkeypatch.setattr(
            lifecycle, "kill_recorded_server",
            lambda port=None, socket_path=None: calls.append(
                {"port": port, "socket_path": socket_path},
            ) or True,
        )
        srv = JoernServer()
        srv._port = 54321
        srv._uds_path = "/nonexistent/raptor-joern-uds-test/sock"
        monkeypatch.setattr(srv, "start", lambda: None)
        assert srv.restart() is True
        assert calls == [{
            "port": 54321,
            "socket_path": "/nonexistent/raptor-joern-uds-test/sock",
        }]


class TestLifecycleKillServer:
    def test_kill_server_reaps_surviving_member(self, _reap_all):
        """The lifecycle grace loop declared victory as soon as the
        LEADER died, even though the JVM member survived — the whole
        tree must be dead before the socket dir teardown."""
        # A leader that dies on SIGTERM (default python) holding a
        # SIGTERM-ignoring member in its group.
        leader_src = (
            "import subprocess, sys, time;"
            "child = subprocess.Popen([sys.executable, '-c', sys.argv[1]],"
            " stdout=subprocess.PIPE, text=True);"
            "child.stdout.readline();"
            "print(child.pid, flush=True);"
            "time.sleep(300)"
        )
        leader = subprocess.Popen(
            [sys.executable, "-c", leader_src, _IGNORING_MEMBER_SRC],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        _reap_all.append(leader.pid)
        assert leader.stdout is not None
        member_pid = int(leader.stdout.readline())
        state = {
            "pid": leader.pid,
            "comm": lifecycle._read_comm(leader.pid),
        }
        lifecycle._kill_server(state)
        leader.wait(timeout=10)
        assert _wait_gone(member_pid), (
            "group member survived the lifecycle kill"
        )

    def test_kill_recorded_server_is_identity_gated(self, monkeypatch):
        killed: list[dict] = []

        def _fake_kill(state):
            killed.append(state)
            return True

        monkeypatch.setattr(lifecycle, "_kill_server", _fake_kill)
        state = {"pid": 1234, "port": 999, "socket_path": "/x/sock"}
        monkeypatch.setattr(
            lifecycle, "_read_state", lambda fd: dict(state),
        )

        class _Fd:
            def __enter__(self):
                return 0

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(lifecycle, "_locked", lambda: _Fd())
        # No identity: refused.
        assert lifecycle.kill_recorded_server() is False
        # Mismatched identity: refused.
        assert lifecycle.kill_recorded_server(port=1000) is False
        assert killed == []
        # Matching port: dispatched.
        assert lifecycle.kill_recorded_server(port=999) is True
        # Matching socket path: dispatched.
        assert lifecycle.kill_recorded_server(
            socket_path="/x/sock",
        ) is True
        assert len(killed) == 2

    def test_kill_recorded_server_reports_comm_gate_refusal(
        self, monkeypatch,
    ):
        """A matched record whose pid the comm gate refuses (reused
        pid, dead leader) dispatched nothing — the return must say
        so, not claim a kill."""
        monkeypatch.setattr(lifecycle, "_kill_server", lambda state: False)
        monkeypatch.setattr(
            lifecycle, "_read_state", lambda fd: {"pid": 1234, "port": 999},
        )

        class _Fd:
            def __enter__(self):
                return 0

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(lifecycle, "_locked", lambda: _Fd())
        assert lifecycle.kill_recorded_server(port=999) is False


class TestPgidAlive:
    def test_reflects_membership_not_leader(self, _reap_all):
        leader, member_pid = _spawn_dead_leader_with_survivor(_reap_all)
        # Leader reaped, member alive: the group must read alive.
        assert _pgid_alive(leader.pid)
        os.kill(member_pid, signal.SIGKILL)
        assert _wait_gone(member_pid)

    def test_none_and_invalid(self):
        assert not _pgid_alive(None)
        assert not _pgid_alive(0)
        assert not _pgid_alive(-5)


class TestNoRegressionFakeProcs:
    def test_stop_with_fake_proc_never_raises(self):
        """The reap tests drive stop() with fake pids (424242-class);
        the group verification must stay inert for them."""
        srv = JoernServer()
        srv._proc = SimpleNamespace(
            pid=2_000_000_000,
            poll=lambda: 0,
            wait=lambda timeout=None: 0,
            terminate=lambda: None,
            kill=lambda: None,
        )
        srv._pgid = 2_000_000_000
        srv.stop()
        assert srv._proc is None
