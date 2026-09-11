"""Regression test for ``_kill_and_reap`` process-group kill.

Pre-fix `_kill_and_reap` only SIGKILLed the direct child PID (the
session leader). Descendants spawned via setsid+fork (e.g. codeql
java → python tracer → multiprocessing forkserver workers) inherited
init as their parent and kept running for weeks. Operators discovered
5 wedged codeql trees still alive 29 days after their parent died,
together holding ~4 CPU-hours.

Fix: ``_kill_and_reap`` now also calls ``os.killpg(pid, SIGKILL)`` to
sweep the leader's process group, killing all descendants in the
same session.

This test pins that fix by:
  1. Spawning a Python child via ``subprocess.Popen(start_new_session=True)``
     so the child becomes a session leader (PGID == its PID).
  2. The child forks its own grandchild that prints its PID then
     sleeps for 60 seconds (long enough to outlive any reasonable
     test timeout).
  3. Parent reads the grandchild PID, then calls ``_kill_and_reap``
     on the child.
  4. Asserts both child AND grandchild are gone within 2 seconds.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.sandbox._spawn import _kill_and_reap

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="/proc required for process liveness check",
)


_GRANDCHILD_SCRIPT = """
import os, sys, time
# Fork once so the original child has a grandchild in the same
# process group (start_new_session=True on the parent put us all in
# one session/group).
pid = os.fork()
if pid == 0:
    # Grandchild: print our PID and idle.
    sys.stdout.write(f"{os.getpid()}\\n")
    sys.stdout.flush()
    time.sleep(60)
else:
    # Original child: also idle, holding the session so the
    # grandchild's PGID stays equal to our PID.
    time.sleep(60)
"""


def _proc_alive(pid: int) -> bool:
    """Check /proc/<pid> existence — works for orphans we don't own."""
    try:
        return Path(f"/proc/{pid}").exists()
    except OSError:
        return False


def test_kill_and_reap_kills_grandchildren_in_session():
    """Spawn a child that forks a grandchild; both should be in the
    same session group. _kill_and_reap on the child must kill BOTH."""
    proc = subprocess.Popen(
        [sys.executable, "-c", _GRANDCHILD_SCRIPT],
        stdout=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        # Read the grandchild PID the script printed.
        line = proc.stdout.readline().decode().strip()
        grandchild_pid = int(line)
        # Confirm both are alive before we kill.
        assert _proc_alive(proc.pid), "child should be alive pre-kill"
        assert _proc_alive(grandchild_pid), "grandchild should be alive pre-kill"

        # Trigger the cleanup path.
        _kill_and_reap(proc.pid)

        # Allow up to 2 seconds for the kill to land + descendants to
        # exit. Poll /proc/<pid>; both should disappear.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if not _proc_alive(proc.pid) and not _proc_alive(grandchild_pid):
                return  # success
            time.sleep(0.05)

        # If we got here, one of them survived. Diagnose for the
        # assertion message.
        child_alive = _proc_alive(proc.pid)
        gc_alive = _proc_alive(grandchild_pid)
        pytest.fail(
            f"_kill_and_reap left descendants: "
            f"child={proc.pid} alive={child_alive}, "
            f"grandchild={grandchild_pid} alive={gc_alive}",
        )
    finally:
        # Belt-and-braces cleanup so a failing test doesn't itself
        # leak the grandchild. SIGKILL the whole group.
        try:
            os.killpg(proc.pid, 9)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass


def test_kill_and_reap_idempotent_on_already_dead_pid():
    """Once a process has exited and been reaped, a second call to
    _kill_and_reap on the same PID must not raise (must be tolerant
    of ProcessLookupError on both the pidfd and killpg paths)."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.exit(0)"],
        start_new_session=True,
    )
    proc.wait(timeout=2)
    # PID has been reaped by .wait. _kill_and_reap must not raise.
    _kill_and_reap(proc.pid)


class TestTeardownTargetSelfGroupGuard:
    """_teardown_target's reaped-path killpg carries the same
    confused-deputy guard as _kill_and_reap: with the supported
    start_new_session=False shape the intermediate's PGID is RAPTOR's
    OWN process group, and an unconditional killpg there SIGKILLed the
    orchestrator (and every unrelated same-group process) on a timeout
    the target itself provoked. Both directions: own group is never
    signalled; a foreign group still gets the descendant sweep."""

    def _teardown(self, popen, monkeypatch):
        from core.sandbox import _spawn
        killed: list[int] = []
        monkeypatch.setattr(os, "killpg",
                            lambda pgid, sig: killed.append(pgid))
        death_r, death_w = os.pipe()
        try:
            # Deliberately NO popen.poll() here: poll() would reap the
            # child, making the entry getpgid raise and the killpg
            # branch unreachable — the guard would pass vacuously.
            # _teardown_target's own grace loop must observe the child
            # as a reapable zombie (the exit-then-reaped path under
            # test).
            _spawn._teardown_target(popen.pid, death_w, {death_w},
                                    grace_s=5.0)
            # _teardown_target reaped the child out from under Popen;
            # record that so the Popen destructor doesn't complain.
            popen.returncode = 0
        finally:
            try:
                os.close(death_r)
            except OSError:
                pass
        return killed

    def test_own_group_never_killpged_on_reaped_path(self, monkeypatch):
        # start_new_session=False: the child shares OUR process group.
        proc = subprocess.Popen(
            [sys.executable, "-c", "pass"], start_new_session=False,
        )
        killed = self._teardown(proc, monkeypatch)
        assert os.getpgrp() not in killed, (
            "reaped-path killpg signalled RAPTOR's own process group")
        assert killed == []

    def test_foreign_group_still_swept_on_reaped_path(self, monkeypatch):
        # start_new_session=True: the child leads its own group — the
        # descendant sweep must still fire there.
        proc = subprocess.Popen(
            [sys.executable, "-c", "pass"], start_new_session=True,
        )
        killed = self._teardown(proc, monkeypatch)
        assert killed == [proc.pid], (
            f"expected exactly the child's group swept, got {killed}")
