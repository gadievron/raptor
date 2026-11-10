"""Descriptor ownership remains explicit while an IO wrapper borrows it."""

from contextlib import ExitStack
import errno
import os

import pytest

from core.source import streams
from core.testing.module_bindings import patch_module_attribute


def assert_closed(fd):
    with pytest.raises(OSError) as caught:
        os.fstat(fd)
    assert caught.value.errno == errno.EBADF


@pytest.fixture
def owned_fd(tmp_path):
    path = tmp_path / "owned"
    path.write_bytes(b"owned bytes")
    with ExitStack() as setup:
        fd = os.open(path, os.O_RDWR)
        setup.callback(os.close, fd)
        info = os.fstat(fd)
        try:
            setup.pop_all()
            yield fd, path
        finally:
            try:
                current = os.fstat(fd)
            except OSError:
                pass
            else:
                if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
                    os.close(fd)


@pytest.mark.parametrize("primary_type", [None, RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [None, OSError, RuntimeError])
def test_raw_owner_consumes_once_and_preserves_primary(owned_fd, primary_type, cleanup_type):
    fd, _ = owned_fd
    primary = primary_type("raw operation failed") if primary_type else None
    cleanup = cleanup_type("raw close failed") if cleanup_type else None
    closed = []

    def close(descriptor):
        os.close(descriptor)
        closed.append(descriptor)
        if cleanup is not None:
            raise cleanup

    def consume():
        with streams.owned_fd(fd, close_fd=close) as descriptor:
            assert descriptor == fd
            if primary is not None:
                raise primary

    expected = primary if primary is not None else cleanup
    if expected is None:
        consume()
    else:
        with pytest.raises(type(expected)) as caught:
            consume()
        assert caught.value is expected
    assert closed == [fd]
    assert_closed(fd)


def test_default_raw_closer_uses_current_consumer_binding(owned_fd, monkeypatch):
    fd, _ = owned_fd
    real_close = os.close
    closed = []

    def close(descriptor):
        real_close(descriptor)
        closed.append(descriptor)

    with streams.owned_fd(fd):
        patch_module_attribute(monkeypatch, streams, "os", "close", close)
    assert closed == [fd]
    assert_closed(fd)


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_failed_adoption_consumes_descriptor(owned_fd, monkeypatch, error_type):
    fd, _ = owned_fd
    error = error_type("adoption failed")
    reached = []

    def fail(descriptor, mode, **kwargs):
        reached.append(descriptor)
        assert kwargs["closefd"] is False
        raise error

    patch_module_attribute(monkeypatch, streams, "os", "fdopen", fail)
    with pytest.raises(error_type) as caught:
        with streams.open_owned_fd(fd, "rb"):
            pytest.fail("failed adoption must not yield")
    assert caught.value is error and reached == [fd]
    assert_closed(fd)


@pytest.mark.parametrize("mode,kwargs,error_type", [
    ("invalid", {}, ValueError),
    ("rb", {"encoding": "utf-8"}, ValueError),
    ("rb", {"closefd": False}, TypeError),
])
def test_invalid_stream_options_still_consume_descriptor(owned_fd, mode, kwargs, error_type):
    fd, _ = owned_fd
    with pytest.raises(error_type):
        with streams.open_owned_fd(fd, mode, **kwargs):
            pytest.fail("invalid options must not yield")
    assert_closed(fd)


@pytest.mark.parametrize("mode", ["r", "rb", "w", "wb"])
def test_success_reads_or_writes_and_closes_both_owners(owned_fd, mode):
    fd, path = owned_fd
    kwargs = {} if "b" in mode else {"encoding": "utf-8"}
    expected = b"owned bytes" if "b" in mode else "owned bytes"
    if mode.startswith("w"):
        os.ftruncate(fd, 0)
    with streams.open_owned_fd(fd, mode, **kwargs) as stream:
        assert stream.fileno() == fd
        if mode.startswith("w"):
            stream.write(expected)
        else:
            assert stream.read() == expected
    assert stream.closed
    assert_closed(fd)
    assert path.read_bytes() == b"owned bytes"


@pytest.mark.parametrize("body_type", [None, RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, RuntimeError])
def test_stream_close_failure_cannot_strand_raw_descriptor(
    owned_fd, monkeypatch, body_type, close_type,
):
    fd, _ = owned_fd
    body = body_type("body failed") if body_type else None
    cleanup = close_type("stream close failed")
    real_fdopen = os.fdopen
    closed = []

    class Stream:
        def __init__(self, raw):
            self.raw = raw

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def close(self):
            self.raw.close()
            closed.append(self.raw.closed)
            raise cleanup

    patch_module_attribute(monkeypatch, streams, "os", "fdopen",
                           lambda *a, **kw: Stream(real_fdopen(*a, **kw)))
    expected = body if body is not None else cleanup
    with pytest.raises(type(expected)) as caught:
        with streams.open_owned_fd(fd, "rb") as stream:
            assert stream.read(1) == b"o"
            if body is not None:
                raise body
    assert caught.value is expected and closed == [True]
    assert_closed(fd)


@pytest.mark.parametrize("body_type", [None, RuntimeError])
@pytest.mark.parametrize("close_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_raw_close_is_attempted_once_with_primary_error_precedence(
    owned_fd, monkeypatch, body_type, close_type,
):
    fd, _ = owned_fd
    body = body_type("body failed") if body_type else None
    cleanup = close_type("raw close failed")
    real_close = os.close
    closed = []

    def close(descriptor):
        real_close(descriptor)
        closed.append(descriptor)
        raise cleanup

    patch_module_attribute(monkeypatch, streams, "os", "close", close)
    expected = body if body is not None else cleanup
    with pytest.raises(type(expected)) as caught:
        with streams.open_owned_fd(fd, "rb"):
            if body is not None:
                raise body
    assert caught.value is expected and closed == [fd]
    assert_closed(fd)
