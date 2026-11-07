"""Pipe helpers retain ownership until allocation and registration succeed."""

import contextlib
import errno
import os

import pytest

from core.sandbox import _spawn as spawn


from core.testing.module_bindings import patch_module_attribute


def assert_closed(fds):
    for fd in fds:
        with pytest.raises(OSError) as exc:
            os.fstat(fd)
        assert exc.value.errno == errno.EBADF


@pytest.mark.parametrize("failure_type", [OSError, MemoryError, KeyboardInterrupt])
def test_second_capture_pipe_failure_closes_first_pair(monkeypatch, failure_type):
    failure = failure_type("second allocation failed")
    real_pipe, real_close = os.pipe, os.close
    allocated, released = [], set()

    def close(fd):
        if fd in allocated:
            released.add(fd)
        real_close(fd)

    def pipe():
        if allocated:
            raise failure
        pair = real_pipe()
        allocated.extend(pair)
        return pair

    try:
        with monkeypatch.context() as patch:
            patch_module_attribute(patch, spawn, 'os', "pipe", pipe)
            patch_module_attribute(patch, spawn, 'os', "close", close)
            with pytest.raises(failure_type) as raised:
                spawn._open_capture_pipes()
        assert raised.value is failure
        assert len(allocated) == 2
        assert_closed(allocated)
    finally:
        for fd in allocated:
            if fd not in released:
                with contextlib.suppress(OSError):
                    real_close(fd)


def test_capture_allocation_transfers_four_usable_descriptors():
    fds = spawn._open_capture_pipes()
    try:
        assert len(set(fds)) == 4
        out_r, out_w, err_r, err_w = fds
        os.write(out_w, b"stdout")
        os.write(err_w, b"stderr")
        assert os.read(out_r, 6) == b"stdout"
        assert os.read(err_r, 6) == b"stderr"
    finally:
        for fd in fds:
            os.close(fd)


@pytest.mark.parametrize("partial_registration", [False, True])
@pytest.mark.parametrize("failure_type", [MemoryError, KeyboardInterrupt])
def test_failed_death_registration_rolls_back_and_closes(
    monkeypatch, partial_registration, failure_type,
):
    failure = failure_type("registration failed")
    before = set(spawn._LIVE_DEATH_W)
    real_pipe, real_close = os.pipe, os.close
    allocated, released = [], set()

    def close(fd):
        if fd in allocated:
            released.add(fd)
        real_close(fd)

    class BrokenRegistry(set):
        def add(self, fd):
            if partial_registration:
                super().add(fd)
            raise failure

    registry = BrokenRegistry(before)

    def pipe():
        pair = real_pipe()
        allocated.extend(pair)
        return pair

    try:
        with monkeypatch.context() as patch:
            patch.setattr(spawn, "_LIVE_DEATH_W", registry)
            patch_module_attribute(patch, spawn, 'os', "pipe", pipe)
            patch_module_attribute(patch, spawn, 'os', "close", close)
            with pytest.raises(failure_type) as raised:
                spawn.open_death_pipe()
        assert raised.value is failure
        assert set(registry) == before
        assert len(allocated) == 2
        assert_closed(allocated)
    finally:
        for fd in allocated:
            if fd not in released:
                with contextlib.suppress(OSError):
                    real_close(fd)


def test_cleanup_error_does_not_replace_allocation_error(monkeypatch):
    failure = OSError(errno.EMFILE, "descriptor table full")
    real_pipe, real_close = os.pipe, os.close
    allocated, closed = [], []

    def pipe():
        if allocated:
            raise failure
        pair = real_pipe()
        allocated.extend(pair)
        return pair

    def close(fd):
        closed.append(fd)
        real_close(fd)
        raise OSError("cleanup reported an error")

    with monkeypatch.context() as patch:
        patch_module_attribute(patch, spawn, 'os', "pipe", pipe)
        patch_module_attribute(patch, spawn, 'os', "close", close)
        with pytest.raises(OSError) as raised:
            spawn._open_capture_pipes()
    assert raised.value is failure
    assert closed == allocated
    assert_closed(allocated)


def test_successful_death_pipe_registration_keeps_close_idempotent():
    read_fd, write_fd = spawn.open_death_pipe()
    try:
        assert write_fd in spawn._LIVE_DEATH_W
        assert spawn.close_death_w(write_fd) is True
        assert spawn.close_death_w(write_fd) is False
        assert write_fd not in spawn._LIVE_DEATH_W
        assert os.read(read_fd, 1) == b""
    finally:
        spawn.close_death_w(write_fd)
        os.close(read_fd)
