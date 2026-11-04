"""Bridge readiness supports high descriptor numbers and terminal events."""

import errno
import fcntl
import os
import resource

import pytest

from core.sandbox._proxy_bridge import _poll_ready


def test_high_numbered_descriptor_is_readable():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    high_min = 2048
    if hard != resource.RLIM_INFINITY and hard <= high_min:
        pytest.skip("host hard limit prevents high descriptor test")
    read_fd, write_fd = os.pipe()
    high_fd = None
    try:
        if soft != resource.RLIM_INFINITY and soft <= high_min:
            resource.setrlimit(resource.RLIMIT_NOFILE, (high_min + 1, hard))
        high_fd = fcntl.fcntl(read_fd, fcntl.F_DUPFD, high_min)
        os.write(write_fd, b"ready")
        assert _poll_ready([high_fd], [], 1) == ([high_fd], [])
        assert os.read(high_fd, 5) == b"ready"
    finally:
        if high_fd is not None:
            os.close(high_fd)
        os.close(read_fd)
        os.close(write_fd)
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def test_closed_writer_wakes_reader():
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    try:
        assert _poll_ready([read_fd], [], 1) == ([read_fd], [])
    finally:
        os.close(read_fd)


def test_writable_and_timeout():
    read_fd, write_fd = os.pipe()
    try:
        assert _poll_ready([read_fd], [write_fd], 0) == ([], [write_fd])
        assert _poll_ready([read_fd], [], 0) == ([], [])
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_invalid_descriptor_reports_ebadf():
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    try:
        with pytest.raises(OSError) as raised:
            _poll_ready([read_fd], [], 0)
        assert raised.value.errno == errno.EBADF
    finally:
        os.close(write_fd)
