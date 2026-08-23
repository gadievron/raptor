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
        [sys.executable, "-c", code], pass_fds=inherit_fds,
    )


def test_drain_survives_idle_gap_while_child_alive(monkeypatch):
    """Output written AFTER a full idle poll interval must not be lost.

    Pre-fix the loop broke on the first silent select() tick, so the
    child's late bytes never reached the caller (and with timeout=None
    the pipes were never read again at all).
    """
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()

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
    out_r, out_w = os.pipe()

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


def test_drain_stops_when_child_exited_and_pipe_held_elsewhere(monkeypatch):
    """When the target has exited but a write end survives elsewhere
    (stray grandchild), the drain must stop after an idle tick instead
    of waiting for an EOF that never comes."""
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    out_r, out_w = os.pipe()

    child = _spawn_child(f"import os; os.write({out_w}, b'gone')", out_w)
    # Parent deliberately KEEPS out_w open — simulates an inherited
    # write end outliving the target.
    try:
        # Let the child exit first so the idle tick sees it gone.
        time.sleep(0.2)
        t0 = time.monotonic()
        drained = mod._drain_pipes_until_eof((out_r,), child.pid)
        elapsed = time.monotonic() - t0
        assert drained[out_r] == b"gone"
        assert elapsed < 5.0, "drain hung despite target having exited"
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
    out_r, out_w = os.pipe()

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


def test_drain_respects_deadline(monkeypatch):
    """A live-but-silent child must not pin the drain past the
    caller's deadline — the caller kills and raises TimeoutExpired."""
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    out_r, out_w = os.pipe()

    # The child must HOLD the write end open while it sleeps (the old
    # fork child inherited it implicitly) — otherwise the drain sees
    # EOF at once and the deadline path is never exercised.
    child = _spawn_child("import time; time.sleep(10.0)", out_w)
    os.close(out_w)
    try:
        deadline = time.monotonic() + 0.3
        t0 = time.monotonic()
        mod._drain_pipes_until_eof((out_r,), child.pid, deadline)
        elapsed = time.monotonic() - t0
        assert elapsed < 2.0, "drain did not stop at the deadline"
    finally:
        os.close(out_r)
        child.kill()
        child.wait(timeout=10)


def test_drain_caps_per_fd_accumulation(monkeypatch):
    """A runaway writer must not balloon the parent: bytes past the
    per-fd cap are read (child stays unblocked) but discarded."""
    monkeypatch.setattr(mod, "_DRAIN_MAX_BYTES_PER_FD", 1024)
    out_r, out_w = os.pipe()

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
