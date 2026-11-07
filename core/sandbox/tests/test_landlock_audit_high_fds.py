"""Audit readiness and draining accept descriptors above FD_SETSIZE."""
import fcntl
import os
import resource
import select
import time

import pytest

from core.sandbox import _landlock_audit as audit
from core.sandbox import _pipe_poll


from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def high_pipe():
    original_limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    changed_limit = False
    read_fd = write_fd = high = None
    writer_open = False

    def close_writer():
        nonlocal writer_open
        if writer_open:
            os.close(write_fd)
            writer_open = False

    try:
        soft, hard = original_limits
        if soft != resource.RLIM_INFINITY and soft <= 1100:
            desired = 2048 if hard == resource.RLIM_INFINITY else min(2048, hard)
            if desired <= 1100:
                pytest.skip('hard descriptor limit is too low')
            resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
            changed_limit = True
        read_fd, write_fd = os.pipe()
        writer_open = True
        high = fcntl.fcntl(read_fd, fcntl.F_DUPFD_CLOEXEC, 1100)
        yield high, write_fd, close_writer
    finally:
        if read_fd is not None:
            os.close(read_fd)
        if high is not None:
            os.close(high)
        close_writer()
        if changed_limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, original_limits)


def test_high_descriptor_readiness_and_eof(high_pipe):
    read_fd, write_fd, close_writer = high_pipe
    assert audit._readable_fds([read_fd], 0) == []
    os.write(write_fd, b'K')
    assert audit._readable_fds([read_fd], 0.1) == [read_fd]
    assert os.read(read_fd, 1) == b'K'
    close_writer()
    assert audit._readable_fds([read_fd], 0.1) == [read_fd]
    assert os.read(read_fd, 1) == b''


def test_high_descriptor_drain_preserves_bytes(high_pipe, monkeypatch):
    read_fd, write_fd, _ = high_pipe
    os.write(write_fd, b'buffered output')
    # The target is already done: final sweep must collect buffered data
    # without waiting for EOF on an inherited writer.
    patch_module_attribute(monkeypatch, audit, 'os', 'waitid', lambda *args: object())
    result = audit._drain_pipes_until_eof([read_fd], 123, deadline=time.monotonic() + 1)
    assert result == {read_fd: b'buffered output'}


@pytest.mark.parametrize('seconds,milliseconds', [(0, 0), (0.0001, 1), (0.25, 250), (None, -1)])
def test_poll_timeout_conversion_preserves_positive_waits(monkeypatch, seconds, milliseconds):
    registrations, waits = [], []

    class Poll:
        def register(self, fd, flags):
            registrations.append((fd, flags))

        def poll(self, timeout):
            waits.append(timeout)
            return [(31, select.POLLHUP)]

    monkeypatch.setattr(_pipe_poll.select, 'poll', Poll)
    assert audit._readable_fds([31], seconds) == [31]
    assert registrations == [(31, select.POLLIN)]
    assert waits == [milliseconds]


def test_empty_descriptor_collection_returns_immediately():
    assert audit._readable_fds([], None) == []
