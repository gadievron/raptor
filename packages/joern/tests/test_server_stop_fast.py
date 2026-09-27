"""Bounded forced-exit teardown (``JoernServer.stop_fast``).

The forced-exit paths of a run (SIGTERM-grace watchdog expiry, second
TERM) must be able to reap a run-private server without the orderly
``stop()``'s multi-phase reap waits: the whole call has to conclude in
a few seconds, TERM-honouring children get a chance to exit, TERM-
ignoring ones are escalated to SIGKILL, and a group that fails
spawn-time corroboration is never signalled at all.

Hermetic — no real JVM. Stand-ins are python children spawned into
their own sessions, mirroring test_stop_group_escalation.py.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from packages.joern import server as server_mod
from packages.joern.server import (
    _FORCED_EXIT_KILL_GRACE_S,
    JoernServer,
    _proc_starttime,
)

# Process-group semantics and starttime corroboration are exercised
# against real children and procfs.
pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="process-group teardown is verified via procfs",
)

_SLEEPER_SRC = "import time; time.sleep(300)"

# Plays the wedged JVM: ignores SIGTERM, only SIGKILL ends it. The
# ready line proves the handler is installed before the test signals.
_IGNORING_SRC = (
    "import signal, time;"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
    "print('ready', flush=True);"
    "time.sleep(300)"
)


def _pid_gone(pid: int) -> bool:
    """Gone, or a zombie awaiting its reaper (killed either way)."""
    try:
        stat = open(f"/proc/{pid}/stat").read()
    except OSError:
        return True
    return stat.rsplit(")", 1)[-1].split()[0] == "Z"


def _wait_gone(pid: int, timeout_s: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _pid_gone(pid):
            return True
        time.sleep(0.05)
    return False


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


def _bare_server_for(proc: subprocess.Popen) -> JoernServer:
    """A handle shaped like a run-private server that owns *proc*."""
    srv = JoernServer.__new__(JoernServer)
    # JoernServer.__del__ runs the REAL stop() at GC — on a hand-built
    # handle that means signalling whatever pid/pgid the test left in
    # place, long after the test's monkeypatches are undone. Neutralise
    # the finalizer on every fabricated handle (instance attr wins over
    # the class method in __del__'s self.stop() lookup).
    srv.stop = lambda: None  # type: ignore[method-assign]
    srv._proc = proc
    srv._pgid = proc.pid
    srv._member_pid = None
    srv._member_starttime = None
    return srv


class TestStopFastRealProcesses:
    def test_cooperative_group_reaped_quickly(self, _reap_all):
        proc = subprocess.Popen(
            [sys.executable, "-c", _SLEEPER_SRC],
            start_new_session=True,
        )
        _reap_all.append(proc.pid)
        srv = _bare_server_for(proc)
        t0 = time.monotonic()
        assert srv.stop_fast(grace_s=2.0) is True
        elapsed = time.monotonic() - t0
        assert _wait_gone(proc.pid, timeout_s=5.0)
        # TERM-honouring child: no full grace phase is consumed, let
        # alone the KILL phase.
        assert elapsed < 2.0 + 1.0, f"stop_fast took {elapsed:.1f}s"
        proc.wait(timeout=5)

    def test_term_ignoring_group_escalates_to_kill_within_bound(
        self, _reap_all,
    ):
        proc = subprocess.Popen(
            [sys.executable, "-c", _IGNORING_SRC],
            stdout=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        _reap_all.append(proc.pid)
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "ready"
        srv = _bare_server_for(proc)
        grace = 1.0
        t0 = time.monotonic()
        assert srv.stop_fast(grace_s=grace) is True
        elapsed = time.monotonic() - t0
        # Two bounded phases (TERM wait exhausted, then KILL) plus
        # slack for the 0.1s poll cadence and process teardown.
        assert elapsed < 2 * grace + 2.0, f"stop_fast took {elapsed:.1f}s"
        assert _wait_gone(proc.pid, timeout_s=5.0)
        proc.wait(timeout=5)

    def test_uncorroborated_group_is_never_signalled(
        self, _reap_all, monkeypatch,
    ):
        """Leader already reaped + anchor mismatch = refuse to signal.

        The pgid was recorded at spawn; by escalation time it could
        name an innocent recycled group. A python sleeper (comm is not
        java/joern) with a wrong-starttime anchor must survive.
        """
        victim = subprocess.Popen(
            [sys.executable, "-c", _SLEEPER_SRC],
            start_new_session=True,
        )
        _reap_all.append(victim.pid)
        real_start = _proc_starttime(victim.pid)
        assert real_start is not None

        sent: list[tuple[int, int]] = []
        real_killpg = os.killpg

        def _recording_killpg(pgid: int, sig: int) -> None:
            if sig != 0:
                sent.append((pgid, sig))
            return real_killpg(pgid, sig)

        monkeypatch.setattr(server_mod.os, "killpg", _recording_killpg)

        srv = JoernServer.__new__(JoernServer)
        srv.stop = lambda: None  # type: ignore[method-assign] — see _bare_server_for
        # Leader handle whose process is long gone (poll() reports an
        # exit) — corroboration must come from the member anchor, and
        # the anchor's starttime deliberately mismatches.
        srv._proc = SimpleNamespace(pid=victim.pid, poll=lambda: 0)
        srv._pgid = victim.pid
        srv._member_pid = victim.pid
        srv._member_starttime = real_start + 1
        assert srv.stop_fast(grace_s=1.0) is False
        assert sent == [], "signalled an uncorroborated group"
        assert not _pid_gone(victim.pid)

    def test_no_proc_is_a_noop(self, monkeypatch):
        sent: list[tuple[int, int]] = []
        monkeypatch.setattr(
            server_mod.os, "killpg",
            lambda pgid, sig: sent.append((pgid, sig)),
        )
        srv = JoernServer.__new__(JoernServer)
        srv.stop = lambda: None  # type: ignore[method-assign] — see _bare_server_for
        assert srv.stop_fast() is True
        assert sent == []

    def test_second_call_after_group_death_is_quick(self, _reap_all):
        proc = subprocess.Popen(
            [sys.executable, "-c", _SLEEPER_SRC],
            start_new_session=True,
        )
        _reap_all.append(proc.pid)
        srv = _bare_server_for(proc)
        assert srv.stop_fast(grace_s=2.0) is True
        proc.wait(timeout=5)
        t0 = time.monotonic()
        assert srv.stop_fast(grace_s=2.0) is True
        assert time.monotonic() - t0 < 1.0

    def test_never_raises(self, monkeypatch):
        srv = JoernServer.__new__(JoernServer)
        srv.stop = lambda: None  # type: ignore[method-assign] — see _bare_server_for
        # NEVER pid 1 / pgid 1 on a fabricated handle: pid 1 passes the
        # "leader of its own group" mock-guard, and killpg(1, sig) is
        # kill(-1, sig) at the kernel — a broadcast to every process
        # this uid can signal. A GC-time __del__ → stop() on exactly
        # that shape SIGTERMed the whole host session fleet.
        srv._proc = SimpleNamespace(pid=2**22 + 12345, poll=lambda: None)
        srv._pgid = 2**22 + 12345
        srv._member_pid = None
        srv._member_starttime = None

        def _boom(*_a, **_k):
            raise RuntimeError("ladder blew up")

        monkeypatch.setattr(server_mod, "_ensure_group_dead", _boom)
        assert srv.stop_fast() is False


class _StubProc:
    """Popen-shaped recorder for hermetic ``stop()`` walks.

    ``poll``/``wait`` report an already-exited child so the reap waits
    return immediately; ``terminate``/``kill`` count the per-process
    fallback deliveries that a refused group signal must fall back to.
    """

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.terminated = 0
        self.killed = 0

    def poll(self) -> int:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def terminate(self) -> None:
        self.terminated += 1

    def kill(self) -> None:
        self.killed += 1


class TestSentinelPgidRefusal:
    """pgid ≤ 1 is never group-signalled — and real pgids still are.

    killpg(1, sig) is kill(-1, sig) at the kernel: a broadcast to every
    same-uid process. pid 1 even passes an "is its own group leader"
    check, so both group-signalling paths (module-level
    ``_ensure_group_dead`` and ``stop()``'s ``_signal_group``) refuse
    pgid ≤ 1 up front. Every killpg here is a recording fake — a
    regressed guard must fail the assertion, never signal for real.
    """

    @pytest.fixture(autouse=True)
    def _fake_killpg(self, monkeypatch):
        self.sent: list[tuple[int, int]] = []
        monkeypatch.setattr(
            server_mod.os, "killpg",
            lambda pgid, sig: self.sent.append((pgid, sig)),
        )

    @pytest.mark.parametrize("pgid", [1, 0, -1])
    def test_ensure_group_dead_refuses_sentinel_pgids(
        self, monkeypatch, pgid,
    ):
        # Force the escalation preconditions TRUE so the pgid guard is
        # the only thing standing between the call and a killpg.
        monkeypatch.setattr(server_mod, "_pgid_alive", lambda _p: True)
        monkeypatch.setattr(
            server_mod, "_group_kill_corroborated", lambda *_a: True,
        )
        assert server_mod._ensure_group_dead(pgid, grace_s=0.05) is True
        assert self.sent == [], f"group-signalled sentinel pgid {pgid}"

    def test_ensure_group_dead_still_signals_real_pgid(self, monkeypatch):
        # Direction two: the wider guard must not swallow legitimate
        # escalations. Alive before TERM, dead after — exactly one
        # SIGTERM to the recorded group.
        pgid = 2**22 + 999
        alive: list[bool] = [True]

        def _fake_alive(_p: int) -> bool:
            state = alive[0]
            alive[0] = False
            return state

        monkeypatch.setattr(server_mod, "_pgid_alive", _fake_alive)
        assert server_mod._ensure_group_dead(
            pgid, grace_s=0.5, corroborated=True,
        ) is True
        assert self.sent == [(pgid, signal.SIGTERM)]

    @pytest.mark.parametrize("pid", [1, 0, -1])
    def test_stop_refuses_sentinel_pid_falls_back_to_proc_handle(
        self, monkeypatch, pid,
    ):
        # A sentinel pid can only come from a corrupted or fabricated
        # handle; stop() must route it to the per-process
        # terminate()/kill() fallback instead of killpg.
        monkeypatch.setattr(server_mod, "_pgid_alive", lambda _p: False)
        proc = _StubProc(pid)
        srv = JoernServer.__new__(JoernServer)
        srv._proc = proc  # type: ignore[assignment]
        srv._pgid = pid
        srv._workdir = None
        try:
            srv.stop()
        finally:
            # Belt-and-braces vs __del__ re-running stop() after the
            # killpg fake is undone (stop() already cleared these on
            # the success path).
            srv._proc = None
            srv._pgid = None
        assert self.sent == [], f"group-signalled sentinel pid {pid}"
        assert proc.terminated == 1
        assert srv._proc is None

    def test_stop_still_group_signals_real_leader(self, monkeypatch):
        # Direction two: a genuine spawn-recorded leader (> 1, leads
        # its own group) still gets the group TERM, not the weaker
        # per-process fallback.
        pid = 2**22 + 777
        monkeypatch.setattr(server_mod.os, "getpgid", lambda p: p)
        monkeypatch.setattr(server_mod, "_pgid_alive", lambda _p: False)
        proc = _StubProc(pid)
        srv = JoernServer.__new__(JoernServer)
        srv._proc = proc  # type: ignore[assignment]
        srv._pgid = pid
        srv._workdir = None
        try:
            srv.stop()
        finally:
            srv._proc = None
            srv._pgid = None
        assert (pid, signal.SIGTERM) in self.sent
        assert proc.terminated == 0


class TestForcedExitGracePins:
    def test_grace_lower_bound(self):
        # Below ~1s a TERM-honouring JVM cannot run its shutdown hook,
        # so every forced exit degrades to SIGKILL + multi-GB kernel
        # address-space teardown.
        assert _FORCED_EXIT_KILL_GRACE_S >= 1.0

    def test_grace_upper_bound(self):
        # Worst case is two bounded phases (TERM wait + KILL wait) =
        # 2×grace; the forced-exit path budgets ~8s total on top of an
        # already-expired salvage grace.
        assert 2 * _FORCED_EXIT_KILL_GRACE_S <= 8.0
