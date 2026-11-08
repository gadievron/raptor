"""Tests for _landlock_audit._drain_pipes_until_eof.

Pins the fix for the stdio drain loop that treated one idle
select() tick as EOF: output written after a silence gap was lost,
and with ``timeout=None`` the parent proceeded to a blocking
``waitpid`` with the pipes never read again — a permanent
parent/child deadlock when the child later filled a pipe buffer.
"""

import os
import subprocess
import sys
import time

import pytest

from core.sandbox import _landlock_audit as mod
from core.testing.pipes import pipes_for_setup

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Landlock audit path is Linux-only",
)


def _spawn_child(code, *inherit_fds):
    """Run *code* in a FRESH single-threaded interpreter, inheriting
    *inherit_fds* (same descriptor numbers, via ``pass_fds``).

    These tests used to fork tiny pipe-writer closures directly, but
    under full-suite order the test process already carries daemon
    threads (the egress-proxy singleton's, started by any earlier
    sandbox test), so a bare fork draws Python's multi-threaded-fork
    DeprecationWarning on every run. The children only write to
    inherited pipe fds and sleep — a subprocess preserves the
    semantics (including being a waitpid-able direct child of the
    test process, which the drain's liveness probe relies on) without
    the fork hazard. The default ``close_fds`` covers what the old
    close-in-child argument did."""
    return subprocess.Popen(
        [sys.executable, "-I", "-S", "-B", "-c", code], pass_fds=inherit_fds,
        env={"PATH": os.defpath},
    )


def test_drain_survives_idle_gap_while_child_alive(monkeypatch):
    """Output written AFTER a full idle poll interval must not be lost.

    Pre-fix the loop broke on the first silent select() tick, so the
    child's late bytes never reached the caller (and with timeout=None
    the pipes were never read again at all).
    """
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    with pipes_for_setup(2) as ((out_r, out_w), (err_r, err_w)):
        # Child: silent for several poll intervals, then speak, then exit.
        child = _spawn_child(
            "import os, time\n"
            "time.sleep(0.5)\n"
            f"os.write({out_w}, b'late-stdout')\n"
            f"os.write({err_w}, b'late-stderr')\n",
            out_w, err_w,
        )
    os.close(out_w)
    os.close(err_w)
    try:
        drained = mod._drain_pipes_until_eof((out_r, err_r), child.pid)
        assert drained[out_r] == b"late-stdout"
        assert drained[err_r] == b"late-stderr"
    finally:
        os.close(out_r)
        os.close(err_r)
        child.wait(timeout=10)


def test_drain_does_not_reap_target(monkeypatch):
    """The liveness probe must leave the exit status for the caller's
    own waitpid (WNOWAIT semantics)."""
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    with pipes_for_setup(1) as ((out_r, out_w),):
        child = _spawn_child(f"import os; os.write({out_w}, b'hi')", out_w)
    os.close(out_w)
    try:
        drained = mod._drain_pipes_until_eof((out_r,), child.pid)
        assert drained[out_r] == b"hi"
        # Must still be reapable — helper may not have consumed it.
        # Raw waitpid (not Popen.wait, which masks ECHILD as "already
        # reaped"): if the drain consumed the exit status this raises
        # ChildProcessError.
        done, status = os.waitpid(child.pid, 0)
        assert done == child.pid
        assert os.waitstatus_to_exitcode(status) == 0
        child.returncode = 0  # reaped above; keep Popen's state honest
    finally:
        os.close(out_r)


def _observe_exited_target_without_blocking(monkeypatch, child):
    # Kernel exit evidence, without consuming the caller's wait status.
    status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
    assert status.si_pid == child.pid
    ready = mod._readable_fds
    waits = []
    def nonblocking(fds, timeout):
        waits.append(timeout)
        assert timeout == 0, "an already-exited target requested a blocking drain"
        return ready(fds, timeout)
    monkeypatch.setattr(mod, "_readable_fds", nonblocking)
    return waits


def test_drain_stops_when_child_exited_and_pipe_held_elsewhere(monkeypatch):
    """A held writer cannot make an already-exited target wait for EOF."""
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    with pipes_for_setup(1) as ((out_r, out_w),):
        child = _spawn_child(f"import os; os.write({out_w}, b'gone')", out_w)
    try:
        waits = _observe_exited_target_without_blocking(monkeypatch, child)
        drained = mod._drain_pipes_until_eof((out_r,), child.pid)
        assert drained[out_r] == b"gone"
        assert waits
    finally:
        os.close(out_w)
        os.close(out_r)
        child.wait(timeout=10)


def test_drain_stops_when_grandchild_chatters_after_target_exit(
        monkeypatch):
    """A grandchild that inherited the write end and writes
    CONTINUOUSLY keeps select() non-empty on every tick, so the
    idle-branch liveness probe never ran — with timeout=None
    (legitimate callers exist, e.g. host.py) the drain, and with it
    the whole run, hung forever after the target exited. The probe
    must run on a time schedule and the post-exit final sweep must be
    bounded even against a still-chattering pipe."""
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    # raising=False: the constant does not exist on pre-fix code, and
    # the test must still reach (and demonstrate) the pre-fix hang.
    monkeypatch.setattr(mod, "_DRAIN_FINAL_SWEEP_S", 0.3, raising=False)
    with pipes_for_setup(1) as ((out_r, out_w),):
        # Target: fork a detached writer that inherits the pipe write end
        # and chatters forever, then exit immediately.
        child = _spawn_child(
            "import os, time\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    while True:\n"
            f"        os.write({out_w}, b'x' * 4096)\n"
            "        time.sleep(0.005)\n"
            "os._exit(0)\n",
            out_w,
        )
    os.close(out_w)
    # The pre-fix behaviour is an unbounded hang, so the drain runs on
    # a worker thread with a generous join budget; the main thread
    # keeps control either way.
    import threading
    result: dict = {}

    def _drain() -> None:
        result["drained"] = mod._drain_pipes_until_eof(
            (out_r,), child.pid, deadline=None)

    t = threading.Thread(target=_drain, daemon=True)
    try:
        t.start()
        t.join(8.0)
        hung = t.is_alive()
    finally:
        # Closing the read end EPIPEs the chattering grandchild on its
        # next write, so nothing outlives the test either way.
        os.close(out_r)
        child.wait(timeout=10)
    assert not hung, (
        "drain hung on a chattering grandchild after the target "
        "exited (timeout=None run)"
    )
    assert result["drained"][out_r].startswith(b"x"), "no bytes collected"


def test_drain_detects_exit_when_deadline_shorter_than_poll_interval(monkeypatch):
    """Known exit is observed before a long configured idle wait."""
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 30.0)
    with pipes_for_setup(1) as ((out_r, out_w),):
        child = _spawn_child(f"import os; os.write({out_w}, b'hello')", out_w)
    try:
        waits = _observe_exited_target_without_blocking(monkeypatch, child)
        drained = mod._drain_pipes_until_eof(
            (out_r,), child.pid, deadline=time.monotonic() + 5.0)
        assert drained[out_r] == b"hello" and waits
    finally:
        os.close(out_w)
        os.close(out_r)
        child.wait(timeout=10)


def test_target_exit_without_pipe_activity_has_a_bounded_liveness_wait(monkeypatch):
    """Exit just after a probe must wake without requiring pipe EOF/data."""
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 30.0)
    with pipes_for_setup(3) as ((out_r, out_w), (ready_r, ready_w), (release_r, release_w)):
        child = _spawn_child(
            f"import os\nos.write({ready_w},b'R')\nos.read({release_r},1)\n",
            out_w, ready_w, release_r)
    remaining = {out_r, out_w, ready_r, ready_w, release_r, release_w}
    def close(fd):
        if fd in remaining:
            remaining.remove(fd)
            os.close(fd)
    readiness = mod._readable_fds
    waits = []
    def release_on_poll(fds, timeout):
        if not waits:
            os.write(release_w, b"X")
        waits.append(timeout)
        assert timeout <= 0.1, "pipe wait can hide a target exit until the caller deadline"
        return readiness(fds, timeout)
    try:
        close(ready_w)
        close(release_r)
        assert os.read(ready_r, 1) == b"R"
        monkeypatch.setattr(mod, "_readable_fds", release_on_poll)
        drained = mod._drain_pipes_until_eof((out_r,), child.pid,
                                             deadline=time.monotonic() + 5.0)
        assert drained[out_r] == b"" and waits
        status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
        assert status.si_pid == child.pid
        assert child.returncode is None, "drain changed the caller's Popen state"
    finally:
        close(release_w)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
        for fd in list(remaining):
            close(fd)


def test_exited_zero_target_with_grandchild_is_not_a_timeout(tmp_path):
    """End-to-end: run_landlock_audit must report the target's real
    exit (rc 0, stdout intact) when a backgrounded grandchild holds
    the stdio write ends past the caller's deadline — never mint
    TimeoutExpired for a target that exited in time. Mirrors _spawn's
    exited-target exemption on the audit lane."""
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available
    if not (check_ptrace_available() and check_seccomp_available()):
        pytest.skip("ptrace/libseccomp unavailable")
    # Two margins pull in opposite directions: the target's echo+exit
    # must land well INSIDE the deadline even on a loaded runner
    # (raise `timeout` if the exit ever races it), while the
    # grandchild must hold the pipes well PAST it (raise its sleep if
    # the deadline ever overtakes the hold). The drain runs to pipe
    # EOF, so the grandchild's sleep is this test's wall-time floor —
    # keep it the smallest value that still clears the deadline
    # comfortably.
    result = mod.run_landlock_audit(
        ["/bin/sh", "-c", "echo hello; sleep 3 & exit 0"],
        audit_run_dir=str(tmp_path),
        timeout=1.5,
        capture_output=True,
    )
    assert result.returncode == 0
    assert "hello" in (result.stdout or "")


def test_drain_respects_deadline(monkeypatch):
    """A live-but-silent child must not pin the drain past the
    caller's deadline — the caller kills and raises TimeoutExpired."""
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    with pipes_for_setup(1) as ((out_r, out_w),):
        # The child must HOLD the write end open while it sleeps (the old
        # fork child inherited it implicitly) — otherwise the drain sees
        # EOF at once and the deadline path is never exercised. Its sleep
        # sits far past the assert bound: a drain that ignores the
        # deadline pins until pipe EOF at child exit (120s), never inside
        # the 20s window a loaded runner could legitimately reach.
        child = _spawn_child("import time; time.sleep(120.0)", out_w)
    os.close(out_w)
    try:
        deadline = time.monotonic() + 0.3
        t0 = time.monotonic()
        mod._drain_pipes_until_eof((out_r,), child.pid, deadline)
        elapsed = time.monotonic() - t0
        from core.testing.wallclock import check_wall_deadline
        check_wall_deadline(
            elapsed, 20.0, code_bound_s=120.0,
            what="drain with a 0.3s deadline and a silent child",
        )
    finally:
        os.close(out_r)
        child.kill()
        child.wait(timeout=10)


def test_drain_caps_per_fd_accumulation(monkeypatch):
    """A runaway writer must not balloon the parent: bytes past the
    per-fd cap are read (child stays unblocked) but discarded."""
    monkeypatch.setattr(mod, "_DRAIN_MAX_BYTES_PER_FD", 1024)
    with pipes_for_setup(1) as ((out_r, out_w),):
        child = _spawn_child(
            "import os\n"
            "payload = b'x' * 256\n"
            "for _ in range(32):  # 8 KiB total, cap is 1 KiB\n"
            f"    os.write({out_w}, payload)\n",
            out_w,
        )
    os.close(out_w)
    try:
        drained = mod._drain_pipes_until_eof((out_r,), child.pid)
        assert len(drained[out_r]) == 1024
        assert drained[out_r] == b"x" * 1024
    finally:
        os.close(out_r)
        child.wait(timeout=10)
