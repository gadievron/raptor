"""Dead-leader kill anchored on the recorded JVM member's starttime.

``_kill_server`` verifies identity via the LEADER pid; a hard kill
landing mid-stop (TERM delivered, forwarder exits, JVM wedges in its
shutdown hook) leaves a dead leader and a live JVM — no live pid to
comm-verify, and an unverified pgid risks the pid-reuse incident
class, so the kill refused and the JVM stayed orphaned. The state
file now carries a boot-derived member anchor (pid +
``/proc/<pid>/stat`` starttime field 22 + comm); a live member whose
current starttime matches the record is provably the recorded
incarnation (starttime is assigned once, at fork — a recycled pid
cannot match) and gets the TERM → wait → KILL ladder. Mismatch or
absence refuses, as before.

Hermetic — no real JVM. Stand-ins are python children; the only fake
pid used is the inert beyond-pid_max 2_000_000_000 (a dead leader),
which no kill path can reach.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from typing import Any

import pytest

from packages.joern import lifecycle
from packages.joern import server as server_mod

# The anchor is procfs-based (starttime, comm, group membership) and
# exercised against real stand-in children.
pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="the member anchor is verified via procfs",
)

_INERT_DEAD_PID = 2_000_000_000  # inert: beyond pid_max

_MEMBER_SRC = "import time; print('ready', flush=True); time.sleep(300)"

# The wedged-JVM stand-in: ignores SIGTERM, only SIGKILL ends it.
_IGNORING_MEMBER_SRC = (
    "import signal, time;"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
    "print('ready', flush=True);"
    "time.sleep(300)"
)


@pytest.fixture(autouse=True)
def _short_grace(monkeypatch):
    """Bound the kill ladder's SIGTERM grace so tests stay fast."""
    monkeypatch.setattr(lifecycle, "_KILL_GRACE_S", 0.5)


def _spawn_member(src: str = _MEMBER_SRC) -> subprocess.Popen:
    """A live stand-in member in the TEST's own process group (it
    does not lead one, so the ladder takes the plain-kill path)."""
    proc = subprocess.Popen(
        [sys.executable, "-c", src],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    proc.stdout.readline()  # ready
    return proc


def _reap(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=10)


def _anchored_state(proc: subprocess.Popen, **overrides: Any) -> dict:
    """Dead-leader state whose member anchor points at *proc*."""
    starttime = server_mod._proc_starttime(proc.pid)
    assert starttime is not None and starttime > 0
    state: dict[str, Any] = {
        "pid": _INERT_DEAD_PID,
        "comm": "java",
        "member_pid": proc.pid,
        "member_starttime": starttime,
        "member_comm": lifecycle._read_comm(proc.pid),
    }
    state.update(overrides)
    return state


class TestDeadLeaderMemberKill:
    def test_matching_starttime_member_is_killed(self):
        member = _spawn_member()
        try:
            state = _anchored_state(member)
            assert lifecycle._kill_server(state) is True
            member.wait(timeout=10)
            assert member.returncode == -signal.SIGTERM
        finally:
            _reap(member)

    def test_sigterm_immune_member_reaches_sigkill(self):
        # The scenario the anchor exists for: the JVM caught TERM and
        # wedged in its shutdown hook — the ladder must escalate.
        member = _spawn_member(_IGNORING_MEMBER_SRC)
        try:
            state = _anchored_state(member)
            assert lifecycle._kill_server(state) is True
            member.wait(timeout=10)
            assert member.returncode == -signal.SIGKILL
        finally:
            _reap(member)

    def test_starttime_mismatch_is_refused(self, caplog):
        # A recycled pid: alive, but a different incarnation than the
        # record — signalling it would be the pid-reuse incident class.
        member = _spawn_member()
        try:
            starttime = server_mod._proc_starttime(member.pid)
            assert starttime is not None
            state = _anchored_state(
                member, member_starttime=starttime + 7,
            )
            with caplog.at_level(
                "WARNING", logger="packages.joern.lifecycle",
            ):
                assert lifecycle._kill_server(state) is False
            assert member.poll() is None, (
                "a starttime-mismatched member must never be signalled"
            )
            assert "recycled" in caplog.text
        finally:
            _reap(member)

    def test_comm_mismatch_is_refused(self):
        member = _spawn_member()
        try:
            state = _anchored_state(member, member_comm="java")
            assert lifecycle._kill_server(state) is False
            assert member.poll() is None
        finally:
            _reap(member)

    def test_absent_member_fields_keep_old_behaviour(self):
        # Old state files carry no anchor — the reap simply declines,
        # exactly as before the anchor existed.
        state = {"pid": _INERT_DEAD_PID, "comm": "java"}
        assert lifecycle._kill_server(state) is False

    def test_dead_member_declines(self):
        state = {
            "pid": _INERT_DEAD_PID,
            "comm": "java",
            "member_pid": _INERT_DEAD_PID,
            "member_starttime": 12345,
            "member_comm": "java",
        }
        assert lifecycle._kill_server(state) is False

    def test_garbage_anchor_shapes_decline(self):
        # Where a shape needs a well-formed pid, only the inert
        # beyond-pid_max value appears — a plausible-real int paired
        # with a garbage sibling must never reach a probe or signal.
        for pid_v, start_v in (
            (True, 12345),
            (_INERT_DEAD_PID, True),
            ("12345", 12345),
            (_INERT_DEAD_PID, "12345"),
            (-1, 12345),
            (None, 12345),
            (_INERT_DEAD_PID, None),
        ):
            state = {
                "pid": _INERT_DEAD_PID,
                "comm": "java",
                "member_pid": pid_v,
                "member_starttime": start_v,
            }
            assert lifecycle._kill_server(state) is False


class TestCleanupMemberReap:
    """``joern_cleanup`` (crash-handler / idle-cleanup path) attempts
    the anchored member reap BEFORE dropping dead-leader state — the
    state file is the last carrier of the anchor that can still reap
    the orphaned JVM."""

    @pytest.fixture(autouse=True)
    def _tmp_state(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lifecycle, "_STATE_DIR", tmp_path)
        monkeypatch.setattr(lifecycle, "_STATE_FILE",
                            tmp_path / "joern-server.json")
        monkeypatch.setattr(lifecycle, "_LOCK_FILE",
                            tmp_path / "joern-server.lock")

    @staticmethod
    def _write_state(state: dict) -> None:
        import json
        lifecycle._STATE_FILE.write_text(json.dumps(state))

    def test_dead_leader_live_member_is_reaped(self):
        member = _spawn_member()
        try:
            self._write_state(_anchored_state(member))
            lifecycle.joern_cleanup()
            member.wait(timeout=10)
            assert member.returncode == -signal.SIGTERM
            assert not lifecycle._STATE_FILE.exists()
        finally:
            _reap(member)

    def test_dead_leader_absent_anchor_unchanged(self):
        # Old state file: no anchor — state is dropped without any
        # signal attempt, exactly the pre-anchor behaviour.
        self._write_state({"pid": _INERT_DEAD_PID, "comm": "java"})
        lifecycle.joern_cleanup()
        assert not lifecycle._STATE_FILE.exists()

    def test_dead_leader_mismatched_anchor_refuses_and_drops_state(self):
        # Recycled member pid: identity gate refuses the kill, the
        # stale state is still removed.
        member = _spawn_member()
        try:
            state = _anchored_state(member)
            state["member_starttime"] = state["member_starttime"] + 1
            self._write_state(state)
            lifecycle.joern_cleanup()
            assert member.poll() is None
            assert not lifecycle._STATE_FILE.exists()
        finally:
            _reap(member)

    def test_live_leader_untouched(self):
        member = _spawn_member()
        try:
            state = _anchored_state(member, pid=os.getpid())
            self._write_state(state)
            lifecycle.joern_cleanup()
            assert member.poll() is None
            assert lifecycle._STATE_FILE.exists()
        finally:
            _reap(member)


class TestBootSideDerivation:
    def _leader_with_stub(self, tmp_path, count: int = 1):
        """A group leader holding *count* java-comm members.

        comm comes from the execve filename, so a symlink to the
        python interpreter named ``java-stub`` yields a member whose
        comm contains ``java`` without any JVM.
        """
        stub = tmp_path / "java-stub"
        stub.symlink_to(sys.executable)
        leader_src = (
            "import subprocess, sys, time;"
            "procs = [subprocess.Popen([sys.argv[1], '-c', sys.argv[2]],"
            " stdout=subprocess.PIPE, text=True)"
            f" for _ in range({count})];"
            "[p.stdout.readline() for p in procs];"
            "print('up', flush=True);"
            "time.sleep(300)"
        )
        leader = subprocess.Popen(
            [sys.executable, "-c", leader_src, str(stub), _MEMBER_SRC],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        assert leader.stdout is not None
        leader.stdout.readline()  # up
        return leader

    def _reap_group(self, leader: subprocess.Popen) -> None:
        try:
            os.killpg(leader.pid, signal.SIGKILL)
        except OSError:
            pass
        leader.wait(timeout=10)

    def test_unambiguous_java_member_is_derived(self, tmp_path):
        leader = self._leader_with_stub(tmp_path)
        try:
            member = server_mod._find_jvm_member(leader.pid)
            assert member is not None
            pid, starttime, comm = member
            assert pid != leader.pid
            assert os.getpgid(pid) == leader.pid
            assert starttime == server_mod._proc_starttime(pid)
            assert "java" in comm
        finally:
            self._reap_group(leader)

    def test_ambiguous_members_fail_safe(self, tmp_path):
        leader = self._leader_with_stub(tmp_path, count=2)
        try:
            assert server_mod._find_jvm_member(leader.pid) is None
        finally:
            self._reap_group(leader)

    def test_no_java_member_fails_safe(self, tmp_path):
        # A fresh session's group holds no java-comm member.  (Never
        # scan the test runner's own group: sibling tests spawn real
        # JVMs -- e.g. the CodeQL CLI -- into it.)
        leader = self._leader_with_stub(tmp_path, count=0)
        try:
            assert server_mod._find_jvm_member(leader.pid) is None
        finally:
            self._reap_group(leader)

    def test_garbage_pgid_fails_safe(self):
        assert server_mod._find_jvm_member(None) is None
        assert server_mod._find_jvm_member(True) is None
        assert server_mod._find_jvm_member(-4) is None

    def test_starttime_of_self_is_positive(self):
        starttime = server_mod._proc_starttime(os.getpid())
        assert isinstance(starttime, int)
        assert starttime > 0

    def test_starttime_of_dead_pid_is_none(self):
        assert server_mod._proc_starttime(_INERT_DEAD_PID) is None


class TestAnchorPersistenceGuards:
    def test_mock_handle_records_absence(self):
        # MagicMock attribute reads return MagicMocks — the write-side
        # shape guard must persist an explicit absence, not garbage
        # that json cannot serialise.
        from unittest.mock import MagicMock

        fields = lifecycle._member_anchor_fields(MagicMock())
        assert fields == {
            "member_pid": None,
            "member_starttime": None,
            "member_comm": None,
        }

    def test_real_anchor_passes_through(self):
        from types import SimpleNamespace

        srv = SimpleNamespace(
            _member_pid=_INERT_DEAD_PID,
            _member_starttime=98765,
            _member_comm="java",
        )
        assert lifecycle._member_anchor_fields(srv) == {
            "member_pid": _INERT_DEAD_PID,
            "member_starttime": 98765,
            "member_comm": "java",
        }

    def test_bool_and_negative_shapes_record_absence(self):
        from types import SimpleNamespace

        for pid_v, start_v in ((True, 5), (5, True), (-5, 5), (5, -5)):
            srv = SimpleNamespace(
                _member_pid=pid_v,
                _member_starttime=start_v,
                _member_comm="java",
            )
            fields = lifecycle._member_anchor_fields(srv)
            assert fields["member_pid"] is None
            assert fields["member_starttime"] is None


class TestKillLadderTiming:
    def test_matching_member_kill_returns_within_grace(self):
        # A TERM-honouring member must not pay the full grace: the
        # ladder polls and returns as soon as the member is gone.
        member = _spawn_member()
        try:
            state = _anchored_state(member)
            began = time.monotonic()
            assert lifecycle._kill_server(state) is True
            assert time.monotonic() - began < 5.0
        finally:
            _reap(member)
