"""Both capture backends wait safely on high-numbered pipes."""
import fcntl
import os
import resource

import pytest

from core.sandbox import _landlock_audit as audit
from core.sandbox import _spawn as spawn
from core.sandbox._pipe_poll import readable_fds


@pytest.fixture(params=[readable_fds, audit._readable_fds, spawn._readable_fds],
                ids=['shared', 'audit', 'spawn'])
def wait(request):
    return request.param


def test_capture_readiness_above_fd_setsize(wait):
    limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    read_fd = write_fd = high = None
    changed_limit = False
    try:
        soft, hard = limits
        if soft != resource.RLIM_INFINITY and soft <= 1100:
            desired = 2048 if hard == resource.RLIM_INFINITY else min(2048, hard)
            if desired <= 1100:
                pytest.skip('hard descriptor limit is too low')
            resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
            changed_limit = True
        read_fd, write_fd = os.pipe()
        high = fcntl.fcntl(read_fd, fcntl.F_DUPFD_CLOEXEC, 1100)
        assert wait([high], 0) == []
        os.write(write_fd, b'output')
        assert wait([high], 0.1) == [high]
        assert os.read(high, 6) == b'output'
        os.close(write_fd)
        write_fd = None
        assert wait([high], 0.1) == [high]
        assert os.read(high, 1) == b''
    finally:
        for fd in (read_fd, write_fd, high):
            if fd is not None:
                os.close(fd)
        if changed_limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, limits)


def test_empty_wait_is_nonblocking(wait):
    assert wait([], None) == []
