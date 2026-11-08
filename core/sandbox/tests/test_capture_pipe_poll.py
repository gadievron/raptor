"""Full-duplex readiness for bounded subprocess I/O."""

from contextlib import contextmanager
import os
import socket

import pytest

from core.sandbox import _pipe_poll as pipe_poll
from core.testing.module_bindings import patch_module_attribute


@contextmanager
def owned_pipe():
    read_fd, write_fd = os.pipe()
    try:
        yield read_fd, write_fd
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_read_and_write_readiness_are_reported_independently():
    with owned_pipe() as (read_fd, write_fd):
        assert pipe_poll.ready_fds([read_fd], [write_fd], 0) == ([], [write_fd])
        os.write(write_fd, b"data")
        assert pipe_poll.ready_fds([read_fd], [write_fd], 0.1) == ([read_fd], [write_fd])
        assert os.read(read_fd, 4) == b"data"


def test_one_descriptor_can_be_watched_in_both_directions():
    left, right = socket.socketpair()
    with left, right:
        right.sendall(b"data")
        assert pipe_poll.ready_fds([left.fileno()], [left.fileno()], 0.1) == ([left.fileno()], [left.fileno()])


def test_hangup_still_reports_readable_buffer_and_eof():
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"data")
    finally:
        os.close(write_fd)
    try:
        assert pipe_poll.ready_fds([read_fd], [], 0.1) == ([read_fd], [])
        assert os.read(read_fd, 4) == b"data"
        assert pipe_poll.ready_fds([read_fd], [], 0.1) == ([read_fd], [])
        assert os.read(read_fd, 1) == b""
    finally:
        os.close(read_fd)


@pytest.mark.parametrize("timeout,expected", [
    pytest.param(None, -1, id="unbounded"),
    pytest.param(-1, 0, id="negative-poll"),
    pytest.param(0, 0, id="immediate"),
    pytest.param(0.0001, 1, id="fractional-ms"),
    pytest.param(1e100, 2147483647, id="large-finite"),
    pytest.param(float("inf"), 2147483647, id="infinity"),
])
def test_poll_timeout_conversion_fits_the_native_argument(monkeypatch, timeout, expected):
    calls = []
    class Poller:
        def register(self, fd, mask):
            calls.append((fd, mask))
        def poll(self, milliseconds):
            assert milliseconds == expected
            return []
    patch_module_attribute(monkeypatch, pipe_poll, "select", "poll", Poller)
    assert pipe_poll.ready_fds([10], [20], timeout) == ([], [])
    assert len(calls) == 2


def test_empty_descriptor_sets_return_without_waiting(monkeypatch):
    def forbidden():
        raise AssertionError("empty readiness constructed a native poller")
    patch_module_attribute(monkeypatch, pipe_poll, "select", "poll", forbidden)
    assert pipe_poll.ready_fds([], [], None) == ([], [])
    assert pipe_poll.readable_fds([], None) == []


def test_invalid_descriptor_wakes_the_owning_io_error_path():
    invalid = 2147483000
    assert pipe_poll.ready_fds([invalid], [invalid], 0) == ([invalid], [invalid])
