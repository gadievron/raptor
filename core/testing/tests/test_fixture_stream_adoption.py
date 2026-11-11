"""Fixture streams transfer descriptors once across native setup failures."""

import errno
import io
import os

import pytest

from core.source import streams as source_streams
from core.testing import streams
from core.testing.module_bindings import patch_module_attribute


def _close_if_owned(fd, identity):
    try:
        info = os.fstat(fd)
    except OSError:
        return
    if (info.st_dev, info.st_ino) == identity:
        os.close(fd)


def test_native_codec_failure_preserves_recycled_fixture_descriptor(tmp_path, monkeypatch):
    path, sentinel = tmp_path / "input", tmp_path / "sentinel"
    path.write_bytes(b"owned input")
    sentinel.write_bytes(b"owned replacement")
    fd = os.open(path, os.O_RDONLY)
    info = os.fstat(fd)
    owned = [(fd, (info.st_dev, info.st_ino))]
    failures = []

    def failed_construction(factory):
        def invoke(*args, **kwargs):
            try:
                return factory(*args, **kwargs)
            except LookupError as primary:
                failures.append(primary)
                with pytest.raises(OSError) as consumed:
                    os.fstat(fd)
                assert consumed.value.errno == errno.EBADF
                replacement = os.open(sentinel, os.O_RDONLY)
                state = os.fstat(replacement)
                owned.append((replacement, (state.st_dev, state.st_ino)))
                assert replacement == fd
                raise
        return invoke

    patch_module_attribute(monkeypatch, streams, "os", "fdopen", failed_construction(os.fdopen))
    patch_module_attribute(monkeypatch, source_streams, "io", "open", failed_construction(io.open))
    try:
        with pytest.raises(LookupError) as raised:
            streams.fdopen_owned(fd, "r", encoding="raptor-owned-unknown-codec")
        assert len(failures) == 1 and raised.value is failures[0]
        assert len(owned) == 2
        assert os.read(owned[1][0], 64) == b"owned replacement"
    finally:
        for descriptor, identity in owned:
            _close_if_owned(descriptor, identity)


@pytest.mark.parametrize("borrowed", [False, True], ids=["owned", "borrowed"])
def test_fdopen_positional_options_and_integer_name(tmp_path, borrowed):
    path = tmp_path / "input"
    path.write_bytes(b"owned bytes")
    fd = os.open(path, os.O_RDONLY)
    info = os.fstat(fd)
    identity = (info.st_dev, info.st_ino)

    def forbidden_opener(*args):
        raise AssertionError("an integer descriptor ignores the supplied opener")

    stream = None
    try:
        stream = streams.fdopen_owned(
            fd, "rb", 0, None, None, None, not borrowed, forbidden_opener,
        )
        assert stream.name == fd
        assert stream.read() == b"owned bytes"
        stream.close()
        if borrowed:
            current = os.fstat(fd)
            assert (current.st_dev, current.st_ino) == identity
        else:
            with pytest.raises(OSError) as closed:
                os.fstat(fd)
            assert closed.value.errno == errno.EBADF
    finally:
        if stream is not None:
            stream.close()
        _close_if_owned(fd, identity)


def test_fdopen_default_text_mode_owns_descriptor(tmp_path):
    path = tmp_path / "input"
    path.write_text("owned text")
    fd = os.open(path, os.O_RDONLY)
    info = os.fstat(fd)
    try:
        with streams.fdopen_owned(fd) as stream:
            assert stream.name == fd
            assert stream.read() == "owned text"
        assert stream.closed
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF
    finally:
        _close_if_owned(fd, (info.st_dev, info.st_ino))


@pytest.mark.parametrize("mode,options,error", [
    ("r", {"unexpected_option": True}, TypeError),
    ("rb", {"encoding": "utf-8"}, ValueError),
])
def test_argument_and_pretransfer_native_failures_close_owned_fd(tmp_path, mode, options, error):
    path = tmp_path / "input"
    path.write_bytes(b"owned input")
    fd = os.open(path, os.O_RDONLY)
    info = os.fstat(fd)
    try:
        with pytest.raises(error):
            streams.fdopen_owned(fd, mode, **options)
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF
    finally:
        _close_if_owned(fd, (info.st_dev, info.st_ino))


def test_argument_failure_keeps_primary_after_close_interrupt(tmp_path, monkeypatch):
    path = tmp_path / "input"
    path.write_bytes(b"owned input")
    fd = os.open(path, os.O_RDONLY)
    info = os.fstat(fd)
    real_close = os.close
    closed = []

    def close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)
        raise KeyboardInterrupt("secondary close interrupt")

    patch_module_attribute(monkeypatch, streams, "os", "close", close)
    try:
        with pytest.raises(TypeError, match="unexpected_option"):
            streams.fdopen_owned(fd, unexpected_option=True)
        assert closed == [fd]
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
    finally:
        _close_if_owned(fd, (info.st_dev, info.st_ino))
