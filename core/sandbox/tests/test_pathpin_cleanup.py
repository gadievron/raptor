"""A failed path walk must release every descriptor it still owns."""

import contextlib
import errno
import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.testing.module_bindings import patch_module_attribute

from core.sandbox import _pathpin as pin

pytestmark = pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="requires Linux O_PATH")


@pytest.fixture
def descriptors(monkeypatch):
    real_open, real_close = os.open, os.close
    owned, opened, closed = set(), [], []

    def open_fd(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        owned.add(fd)
        opened.append(fd)
        return fd

    def close_fd(fd):
        closed.append(fd)
        if fd in opened and fd not in owned:
            # Never let a regressed duplicate close touch a reused fd.
            raise OSError(errno.EBADF, "duplicate close intercepted")
        owned.discard(fd)
        real_close(fd)

    patch_module_attribute(monkeypatch, pin, 'os', "open", open_fd)
    patch_module_attribute(monkeypatch, pin, 'os', "close", close_fd)
    try:
        yield SimpleNamespace(owned=owned, opened=opened, closed=closed, close=close_fd)
    finally:
        for fd in list(owned):
            with contextlib.suppress(OSError):
                real_close(fd)


@pytest.mark.parametrize("failure_type", [OSError, RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("component", [1, 2])
def test_component_stat_failure_releases_both_pins(
    tmp_path, monkeypatch, descriptors, failure_type, component,
):
    failure = failure_type("component stat failed")
    real_fstat = os.fstat
    calls = []

    def fstat(fd):
        calls.append(fd)
        if len(calls) == component:
            raise failure
        return real_fstat(fd)

    patch_module_attribute(monkeypatch, pin, 'os', "fstat", fstat)
    with pytest.raises(failure_type) as raised:
        pin.open_pinned(str(tmp_path))
    assert raised.value is failure
    assert descriptors.owned == set()


def test_previous_pin_close_error_does_not_close_it_twice(tmp_path, monkeypatch, descriptors):
    failure = OSError("close reported an error after releasing the fd")
    failed = []

    def close(fd):
        descriptors.close(fd)
        if not failed:
            failed.append(fd)
            raise failure

    patch_module_attribute(monkeypatch, pin, 'os', "close", close)
    with pytest.raises(OSError) as raised:
        pin.open_pinned(str(tmp_path))
    assert raised.value is failure
    assert descriptors.owned == set()
    assert descriptors.closed.count(failed[0]) == 1


def test_cleanup_error_preserves_original_stat_failure(tmp_path, monkeypatch, descriptors):
    failure = RuntimeError("stat failed")
    failed_close = []

    def close(fd):
        descriptors.close(fd)
        if not failed_close:
            failed_close.append(fd)
            raise OSError("cleanup failed")

    patch_module_attribute(monkeypatch, pin, 'os', "fstat", Mock(side_effect=failure))
    patch_module_attribute(monkeypatch, pin, 'os', "close", close)
    with pytest.raises(RuntimeError) as raised:
        pin.open_pinned(str(tmp_path))
    assert raised.value is failure
    assert descriptors.owned == set()


def test_success_transfers_only_the_final_pin(tmp_path, descriptors):
    expected = tmp_path.stat()
    fd = pin.open_pinned(str(tmp_path))
    try:
        assert descriptors.owned == {fd}
        actual = os.fstat(fd)
        assert (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)
        assert not os.get_inheritable(fd)
    finally:
        descriptors.close(fd)


def test_initial_open_failure_preserves_error_without_closing_none(monkeypatch, descriptors):
    failure = OSError(errno.EMFILE, "descriptor table full")
    patch_module_attribute(monkeypatch, pin, 'os', "open", Mock(side_effect=failure))
    with pytest.raises(OSError) as raised:
        pin.open_pinned("/")
    assert raised.value is failure
    assert descriptors.closed == []
