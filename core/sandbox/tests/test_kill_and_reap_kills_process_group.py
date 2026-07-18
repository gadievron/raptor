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

import pytest  # noqa: F401  (kept for pytest.fail in error paths below)

from core.sandbox._spawn import _kill_and_reap


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
