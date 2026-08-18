"""Tests for _landlock_audit._drain_pipes_until_eof.

Pins the fix for the stdio drain loop that treated one idle
select() tick as EOF: output written after a silence gap was lost,
and with ``timeout=None`` the parent proceeded to a blocking
``waitpid`` with the pipes never read again — a permanent
parent/child deadlock when the child later filled a pipe buffer.
"""

import os
import sys
import time

import pytest

from core.sandbox import _landlock_audit as mod

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Landlock audit path is Linux-only",
)


def _fork_child(child_fn, *close_in_child):
    pid = os.fork()
    if pid == 0:
        try:
            for fd in close_in_child:
                os.close(fd)
            child_fn()
        finally:
            os._exit(0)
    return pid


def test_drain_survives_idle_gap_while_child_alive(monkeypatch):
    """Output written AFTER a full idle poll interval must not be lost.

    Pre-fix the loop broke on the first silent select() tick, so the
    child's late bytes never reached the caller (and with timeout=None
    the pipes were never read again at all).
    """
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()

    def child():
        # Silent for several poll intervals, then speak, then exit.
        time.sleep(0.5)
        os.write(out_w, b"late-stdout")
        os.write(err_w, b"late-stderr")

    pid = _fork_child(child, out_r, err_r)
    os.close(out_w)
    os.close(err_w)
    try:
        drained = mod._drain_pipes_until_eof((out_r, err_r), pid)
        assert drained[out_r] == b"late-stdout"
        assert drained[err_r] == b"late-stderr"
    finally:
        os.close(out_r)
        os.close(err_r)
        os.waitpid(pid, 0)


def test_drain_does_not_reap_target(monkeypatch):
    """The liveness probe must leave the exit status for the caller's
    own waitpid (WNOWAIT semantics)."""
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    out_r, out_w = os.pipe()

    def child():
        os.write(out_w, b"hi")

    pid = _fork_child(child, out_r)
    os.close(out_w)
    try:
        drained = mod._drain_pipes_until_eof((out_r,), pid)
        assert drained[out_r] == b"hi"
        # Must still be reapable — helper may not have consumed it.
        done, status = os.waitpid(pid, 0)
        assert done == pid
        assert os.waitstatus_to_exitcode(status) == 0
    finally:
        os.close(out_r)


def test_drain_stops_when_child_exited_and_pipe_held_elsewhere(monkeypatch):
    """When the target has exited but a write end survives elsewhere
    (stray grandchild), the drain must stop after an idle tick instead
    of waiting for an EOF that never comes."""
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    out_r, out_w = os.pipe()

    def child():
        os.write(out_w, b"gone")

    pid = _fork_child(child, out_r)
    # Parent deliberately KEEPS out_w open — simulates an inherited
    # write end outliving the target.
    try:
        # Let the child exit first so the idle tick sees it gone.
        time.sleep(0.2)
        t0 = time.monotonic()
        drained = mod._drain_pipes_until_eof((out_r,), pid)
        elapsed = time.monotonic() - t0
        assert drained[out_r] == b"gone"
        assert elapsed < 5.0, "drain hung despite target having exited"
    finally:
        os.close(out_w)
        os.close(out_r)
        os.waitpid(pid, 0)


def test_drain_respects_deadline(monkeypatch):
    """A live-but-silent child must not pin the drain past the
    caller's deadline — the caller kills and raises TimeoutExpired."""
    monkeypatch.setattr(mod, "_DRAIN_IDLE_POLL_S", 0.05)
    out_r, out_w = os.pipe()

    def child():
        time.sleep(10.0)

    pid = _fork_child(child, out_r)
    os.close(out_w)
    try:
        deadline = time.monotonic() + 0.3
        t0 = time.monotonic()
        mod._drain_pipes_until_eof((out_r,), pid, deadline)
        elapsed = time.monotonic() - t0
        assert elapsed < 2.0, "drain did not stop at the deadline"
    finally:
        os.close(out_r)
        os.kill(pid, 9)
        os.waitpid(pid, 0)


def test_drain_caps_per_fd_accumulation(monkeypatch):
    """A runaway writer must not balloon the parent: bytes past the
    per-fd cap are read (child stays unblocked) but discarded."""
    monkeypatch.setattr(mod, "_DRAIN_MAX_BYTES_PER_FD", 1024)
    out_r, out_w = os.pipe()

    def child():
        payload = b"x" * 256
        for _ in range(32):  # 8 KiB total, cap is 1 KiB
            os.write(out_w, payload)

    pid = _fork_child(child, out_r)
    os.close(out_w)
    try:
        drained = mod._drain_pipes_until_eof((out_r,), pid)
        assert len(drained[out_r]) == 1024
        assert drained[out_r] == b"x" * 1024
    finally:
        os.close(out_r)
        os.waitpid(pid, 0)
