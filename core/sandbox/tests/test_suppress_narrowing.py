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

import errno
import os
import threading

import pytest

from core.sandbox.host import HostRPCError, SandboxHost


def _make_host() -> SandboxHost:
    """Minimal SandboxHost with real (unconnected) pipe fds and a
    finished worker thread — enough state for close() to run."""
    read_fd, write_fd = os.pipe()
    try:
        thread = threading.Thread(target=lambda: None)
        host = SandboxHost(
            _thread=thread,
            _read_fd=read_fd,
            _write_fd=write_fd,
            _daemon_fds=None,
            _lock=threading.Lock(),
        )
        thread.start()
        thread.join()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    return host


def test_miswired_close_rpc_propagates_typeerror():
    """A TypeError out of the close RPC (miswiring class) is no longer
    swallowed by close()."""
    host = _make_host()

    def _boom(payload, *, timeout):
        raise TypeError("miswired call shape")

    host._rpc = _boom
    owned = {
        fd: (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        for fd in (host._read_fd, host._write_fd)
    }
    try:
        with pytest.raises(TypeError, match="miswired call shape"):
            host.close()
        assert host._read_fd is None and host._write_fd is None
        assert not host._thread.is_alive()
        for fd in owned:
            with pytest.raises(OSError) as caught:
                os.fstat(fd)
            assert caught.value.errno == errno.EBADF
    finally:
        # Independently reclaim a regressed implementation's still-owned
        # pipes; consumed or reused descriptor numbers are never closed again.
        for fd, identity in owned.items():
            try:
                info = os.fstat(fd)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    continue
                raise
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)


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
