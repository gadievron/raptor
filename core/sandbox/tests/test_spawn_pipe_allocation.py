"""Pipe helpers retain ownership until allocation and registration succeed."""

import contextlib
import errno
import os
import threading
from types import SimpleNamespace

import pytest

from core.sandbox import _spawn as spawn


from core.testing.module_bindings import patch_module_attribute
from core.testing.module_views import module_function_view


def assert_closed(fds, identities=None):
    for fd in fds:
        if identities is None:
            with pytest.raises(OSError) as exc:
                os.fstat(fd)
            assert exc.value.errno == errno.EBADF
            continue
        try:
            info = os.fstat(fd)
        except OSError as exc:
            assert exc.errno == errno.EBADF
            continue
        assert (info.st_dev, info.st_ino) != identities[fd], "original pipe end is still open"


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


@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("fault_site", ["first", "last", "both"])
def test_cleanup_error_does_not_replace_allocation_error(monkeypatch, cleanup_type, fault_site):
    failure = OSError(errno.EMFILE, "descriptor table full")
    cleanup = cleanup_type("cleanup reported an error")
    real_pipe, real_close = os.pipe, os.close
    allocated, closed, identities = [], [], {}

    def pipe():
        if allocated:
            raise failure
        pair = real_pipe()
        for fd in pair:
            info = os.fstat(fd)
            identities[fd] = (info.st_dev, info.st_ino)
        allocated.extend(pair)
        return pair

    def close(fd):
        real_close(fd)
        closed.append(fd)
        if (fault_site == "both" or
                fd == allocated[0 if fault_site == "first" else -1]):
            raise cleanup

    try:
        with monkeypatch.context() as patch:
            patch_module_attribute(patch, spawn, 'os', "pipe", pipe)
            patch_module_attribute(patch, spawn, 'os', "close", close)
            with pytest.raises(BaseException) as raised:
                spawn._open_capture_pipes()
        assert raised.value is failure
        assert closed == allocated
        assert_closed(allocated, identities)
    finally:
        for fd, identity in identities.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                real_close(fd)


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


@pytest.mark.parametrize("partial_registration", [False, True])
@pytest.mark.parametrize("failure_type", [MemoryError, KeyboardInterrupt])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("fault_end", [0, 1], ids=["read-end", "write-end"])
def test_death_registration_cleanup_attempts_both_ends_and_preserves_error(
    partial_registration, failure_type, cleanup_type, fault_end,
):
    primary = failure_type("owned registry failure")
    secondary = cleanup_type("owned close failure")
    allocated, closed, identities = [], [], {}
    native_pipe, native_close = os.pipe, os.close

    class Registry(set):
        def add(self, fd):
            if partial_registration:
                super().add(fd)
            raise primary

    registry = Registry()
    lock = threading.Lock()

    def pipe():
        pair = native_pipe()
        allocated.extend(pair)
        for fd in pair:
            info = os.fstat(fd)
            identities[fd] = (info.st_dev, info.st_ino)
        return pair

    def close(fd):
        native_close(fd)
        closed.append(fd)
        if fd == allocated[fault_end]:
            raise secondary

    local_os = SimpleNamespace(**vars(os))
    local_os.pipe, local_os.close = pipe, close
    view = module_function_view(spawn, bindings={
        "os": local_os, "_LIVE_DEATH_W": registry, "_DEATH_W_LOCK": lock,
    })
    try:
        with pytest.raises(BaseException) as caught:
            view.open_death_pipe()
        assert caught.value is primary
        assert closed == allocated and len(closed) == 2
        assert_closed(allocated, identities)
        assert registry == set() and not lock.locked()
    finally:
        for fd, identity in identities.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                native_close(fd)


def test_physical_pipe_oracle_rejects_leak_and_accepts_a_recycled_number():
    fds = []
    identities = {}
    try:
        for _ in range(2):
            pair = os.pipe()
            fds.extend(pair)
            for fd in pair:
                info = os.fstat(fd)
                identities[fd] = (info.st_dev, info.st_ino)
        target, _, source, writer = fds
        original = {target: identities[target]}
        with pytest.raises(AssertionError, match="original pipe end"):
            assert_closed([target], original)
        # Replace an owned descriptor atomically; there is no interval where
        # another thread could allocate a borrowed handle at this number.
        os.dup2(source, target)
        info = os.fstat(target)
        identities[target] = (info.st_dev, info.st_ino)
        assert identities[target] != original[target]
        assert_closed([target], original)
        os.write(writer, b"x")
        assert os.read(target, 1) == b"x"
    finally:
        for fd, identity in identities.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)
