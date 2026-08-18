"""Narrowed best-effort handlers must no longer eat miswiring-class
exceptions.

Representative fails-before test for the core/sandbox
``contextlib.suppress(Exception)`` narrowing sweep: before the sweep,
``SandboxHost.close()`` wrapped its close RPC in ``suppress(Exception)``,
so a miswired ``_rpc`` call (e.g. wrong argument shape → TypeError)
vanished silently.  After narrowing to ``(HostRPCError, ValueError)``
the legitimate best-effort cases (dead daemon, malformed reply) still
pass while a TypeError propagates.
"""
from __future__ import annotations

import os
import threading

import pytest

from core.sandbox.host import HostRPCError, SandboxHost


def _make_host() -> SandboxHost:
    """Minimal SandboxHost with real (unconnected) pipe fds and a
    finished worker thread — enough state for close() to run."""
    host = SandboxHost.__new__(SandboxHost)
    host._closed = False
    host._daemon_fds = None
    host._read_fd, host._write_fd = os.pipe()
    host._thread = threading.Thread(target=lambda: None)
    host._thread.start()
    host._thread.join()
    return host


def test_miswired_close_rpc_propagates_typeerror():
    """A TypeError out of the close RPC (miswiring class) is no longer
    swallowed by close()."""
    host = _make_host()

    def _boom(payload, *, timeout):
        raise TypeError("miswired call shape")

    host._rpc = _boom
    with pytest.raises(TypeError, match="miswired call shape"):
        host.close()
    # close() still released the pipe fds before the RPC — clean up
    # whatever the failed close left open.
    for fd in (host._read_fd, host._write_fd):
        try:
            os.close(fd)
        except OSError:
            pass


@pytest.mark.parametrize(
    "exc",
    [HostRPCError("daemon EOF"), ValueError("malformed daemon reply")],
)
def test_legitimate_close_rpc_failures_still_suppressed(exc):
    """The best-effort intent is preserved: channel failures and
    malformed replies from a dying daemon do not escape close()."""
    host = _make_host()

    def _dead(payload, *, timeout):
        raise exc

    host._rpc = _dead
    host.close()  # must not raise
    assert host._closed is True
