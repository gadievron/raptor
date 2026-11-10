"""Audit streams transfer descriptor ownership exactly once during setup."""

from __future__ import annotations

import errno
import io
import logging
import os

import pytest

import core.logging as audit
from core.source import streams
from core.testing.module_bindings import patch_module_attribute


def _record(message="audit event"):
    return logging.LogRecord("raptor", logging.INFO, __file__, 1, message, (), None)


def test_native_codec_failure_preserves_primary_and_existing_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("prior record\n")
    handler = audit._OwnerOnlyFileHandler(path, encoding="raptor-no-such-audit-codec", delay=True)
    try:
        with pytest.raises(LookupError, match="unknown encoding"):
            handler.emit(_record())
        assert handler.stream is None
        assert path.read_text() == "prior record\n"
    finally:
        handler.close()


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("transferred", [False, True], ids=["before-transfer", "after-transfer"])
def test_stream_setup_retires_only_its_owned_descriptor(tmp_path, monkeypatch, error_type, transferred):
    path = tmp_path / "audit.jsonl"
    sentinel_path = tmp_path / "sentinel"
    sentinel_path.write_bytes(b"owned sentinel")
    original_open, original_close = os.open, os.close
    primary = error_type("stream setup failed")
    allocated, closed, sentinels = [], [], []

    def allocate(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        info = os.fstat(fd)
        allocated.append((fd, info.st_dev, info.st_ino))
        return fd

    def close(fd):
        original_close(fd)
        closed.append(fd)
        raise OSError("secondary close failure")

    def factory(name, mode, *, opener, **kwargs):
        assert mode == "a" and kwargs["encoding"] == "utf-8"
        assert allocated
        if transferred:
            fd = opener(name, os.O_WRONLY)
            assert fd == allocated[0][0]
            original_close(fd)
            replacement = original_open(sentinel_path, os.O_RDONLY)
            assert replacement == fd
            info = os.fstat(replacement)
            sentinels.append((replacement, info.st_dev, info.st_ino))
        raise primary

    patch_module_attribute(monkeypatch, audit, "os", "open", allocate)
    patch_module_attribute(monkeypatch, audit, "os", "close", close)
    patch_module_attribute(monkeypatch, streams, "io", "open", factory)
    handler = audit._OwnerOnlyFileHandler(path, encoding="utf-8", delay=True)
    try:
        with pytest.raises(error_type) as caught:
            handler.emit(_record())
        assert caught.value is primary
        assert len(allocated) == 1 and handler.stream is None
        if transferred:
            assert closed == []
            assert os.read(sentinels[0][0], 32) == b"owned sentinel"
        else:
            assert closed == [allocated[0][0]]
            with pytest.raises(OSError) as absent:
                os.fstat(allocated[0][0])
            assert absent.value.errno == errno.EBADF
    finally:
        handler.close()
        for fd, device, inode in [*sentinels, *allocated]:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == (device, inode):
                original_close(fd)


def test_success_preserves_encoding_errors_and_append_mode(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"prior record\n")
    handler = audit._OwnerOnlyFileHandler(path, encoding="ascii", errors="backslashreplace", delay=True)
    try:
        assert handler.stream is None
        handler.emit(_record("caf\u00e9"))
        assert handler.stream is not None and isinstance(handler.stream, io.TextIOWrapper)
        assert isinstance(handler.stream.name, int)
        descriptor = handler.stream.fileno()
        assert not os.get_inheritable(descriptor)
    finally:
        handler.close()
    assert path.read_bytes() == b"prior record\ncaf\\xe9\n"
    with pytest.raises(OSError) as absent:
        os.fstat(descriptor)
    assert absent.value.errno == errno.EBADF
