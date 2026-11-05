"""Post-fork handshake waits work with high descriptors and fixed deadlines."""
import fcntl
import os
import resource
import signal
import time
from unittest.mock import Mock

import pytest

from core.sandbox import _spawn as spawn


@pytest.fixture
def high_pipe():
    limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    changed = False
    read_fd = write_fd = high = None

    def close_writer():
        nonlocal write_fd
        if write_fd is not None:
            os.close(write_fd)
            write_fd = None

    try:
        soft, hard = limits
        if soft != resource.RLIM_INFINITY and soft <= 1100:
            desired = 2048 if hard == resource.RLIM_INFINITY else min(2048, hard)
            if desired <= 1100:
                pytest.skip('hard descriptor limit is too low')
            resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
            changed = True
        read_fd, write_fd = os.pipe()
        high = fcntl.fcntl(read_fd, fcntl.F_DUPFD_CLOEXEC, 1100)
        yield high, write_fd, close_writer
    finally:
        for fd in (read_fd, write_fd, high):
            if fd is not None:
                os.close(fd)
        if changed:
            resource.setrlimit(resource.RLIMIT_NOFILE, limits)


def test_high_go_pipe_ready_byte(high_pipe):
    read_fd, write_fd, _ = high_pipe
    os.write(write_fd, b'G')
    assert spawn._pipe_readable_until(read_fd, time.monotonic() + 5)
    assert os.read(read_fd, 1) == b'G'


def test_high_go_pipe_timeout(high_pipe):
    read_fd, _, _ = high_pipe
    assert spawn._pipe_readable_until(read_fd, time.monotonic() + 0.01) is False


def test_expired_deadline_is_not_extended_by_buffered_data(high_pipe):
    read_fd, write_fd, _ = high_pipe
    os.write(write_fd, b'G')
    assert spawn._pipe_readable_until(read_fd, time.monotonic() - 1) is False


def test_interrupted_wait_rechecks_original_deadline(monkeypatch):
    poller = Mock()
    poller.poll.side_effect = InterruptedError()
    monkeypatch.setattr(spawn._select_mod, 'poll', lambda: poller)
    with monkeypatch.context() as scoped:
        scoped.setattr(spawn.time, 'monotonic', Mock(side_effect=[100.0, 106.0]))
        assert spawn._pipe_readable_until(31, 105.0) is False
    assert poller.poll.call_count == 1


@pytest.mark.skipif(not hasattr(os, 'fork'), reason='requires fork')
def test_high_go_wait_in_forked_child(high_pipe):
    read_fd, write_fd, _ = high_pipe
    os.write(write_fd, b'G')
    child = os.fork()
    if child == 0:
        try:
            ready = spawn._pipe_readable_until(read_fd, time.monotonic() + 10)
            ok = ready and os.read(read_fd, 1) == b'G'
        except BaseException:
            os._exit(90)
        os._exit(0 if ok else 91)
    owned = True
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            waited, status = os.waitpid(child, os.WNOHANG)
            if waited == child:
                owned = False
                assert os.waitstatus_to_exitcode(status) == 0
                break
            time.sleep(0.01)
        else:
            pytest.fail('post-fork pipe wait did not finish')
    finally:
        if owned:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)


def test_high_go_pipe_eof_is_readable(high_pipe):
    read_fd, _, close_writer = high_pipe
    close_writer()
    assert spawn._pipe_readable_until(read_fd, time.monotonic() + 5)
    assert os.read(read_fd, 1) == b''
