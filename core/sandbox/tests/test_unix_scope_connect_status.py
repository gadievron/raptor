"""A readiness wake does not prove that an owned connect succeeded."""

import ctypes
import errno
import fcntl
import os
import select
import socket
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import _unix_scope as scope
from core.testing.module_bindings import patch_module_attribute


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux Unix-scope backend')


@pytest.mark.parametrize('status, expected', [
    pytest.param(None, -errno.EPERM, id='unreadable-status'),
    pytest.param(0, 0, id='confirmed-success'),
    pytest.param(errno.ECONNREFUSED, -errno.ECONNREFUSED, id='confirmed-refusal'),
])
def test_connect_completion_requires_readable_socket_status(monkeypatch, status, expected):
    # Drive the production completion branch without a socket, syscall or
    # supervisor thread. Every descriptor operation is intercepted below.
    descriptor = 123
    flags = []
    reads = []

    def control(fd, operation, value=None):
        assert fd == descriptor
        if operation == fcntl.F_GETFL:
            return 0
        assert operation == fcntl.F_SETFL
        flags.append(value)
        return 0

    def connect(fd, address, length):
        assert (fd, address, length) == (descriptor, b'owned-address', 13)
        ctypes.set_errno(errno.EINPROGRESS)
        return -1

    class Poller:
        def register(self, fd, mask):
            assert (fd, mask) == (descriptor, select.POLLOUT)

        def poll(self, timeout):
            assert 0 < timeout <= 500
            return [(descriptor, select.POLLOUT)]

    def socket_status(fd, level, option):
        assert (fd, level, option) == (descriptor, socket.SOL_SOCKET, socket.SO_ERROR)
        reads.append(True)
        return status

    supervisor = object.__new__(scope.UnixScopeSupervisor)
    supervisor._closed = SimpleNamespace(is_set=lambda: False)
    monkeypatch.setattr(scope, '_get_libc', lambda: SimpleNamespace(connect=connect))
    monkeypatch.setattr(scope, '_getsockopt_int', socket_status)
    patch_module_attribute(monkeypatch, scope, 'fcntl', 'fcntl', control)
    monkeypatch.setattr(select, 'poll', Poller)
    saved_errno = ctypes.get_errno()
    try:
        assert supervisor._connect_raw(descriptor, b'owned-address') == (expected, 0)
    finally:
        ctypes.set_errno(saved_errno)
    assert reads == [True]
    assert flags == [os.O_NONBLOCK, os.O_NONBLOCK, 0]
