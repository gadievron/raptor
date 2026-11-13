"""Owned EOCD path readers preserve read failures during teardown."""
import errno
import io
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.zip import eocd


@pytest.fixture
def archive(tmp_path, monkeypatch):
    path = tmp_path / 'owned.zip'
    payload = b'PK\x05\x06' + bytes(18)
    path.write_bytes(payload)
    state = SimpleNamespace(path=path, payload=payload, primary=None, cleanup=None,
                            reads=[], streams=[], closes=0, fd=None)

    class Reader(io.BufferedReader):
        def read(self, size=-1):
            data = super().read(size)
            state.reads.append((size, data))
            if state.primary is not None:
                raise state.primary
            return data

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    class OwnedPath(type(Path())):
        def open(self, mode='r', *args, **kwargs):
            assert self == path and mode == 'rb' and not args and not kwargs
            native = path.open(mode)
            state.fd = native.fileno()
            info, expected = os.fstat(state.fd), path.stat()
            assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
            reader = Reader(native)
            state.streams.extend([native, reader])
            return reader

    monkeypatch.setattr(eocd, 'Path', OwnedPath)
    state.run = lambda: eocd.peek_eocd(path)
    try:
        yield state
    finally:
        for stream in reversed(state.streams):
            if not stream.closed:
                io.BufferedReader.close(stream)
        if path.exists():
            assert path.read_bytes() == payload


def retired(archive):
    assert archive.reads == [(22, archive.payload)]
    assert archive.closes == 1 and all(stream.closed for stream in archive.streams)
    with pytest.raises(OSError) as caught:
        os.fstat(archive.fd)
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_public_path_read_error_survives_consumed_close(archive, primary, cleanup):
    archive.primary = primary('after native owned EOCD read')
    archive.cleanup = cleanup('after consumed EOCD close')
    with pytest.raises(primary) as caught:
        archive.run()
    assert caught.value is archive.primary
    retired(archive)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt, MemoryError])
def test_public_path_fresh_close_keeps_policy(archive, cleanup):
    archive.cleanup = cleanup('fresh EOCD close failure')
    if cleanup is OSError:
        assert archive.run() is None
    else:
        with pytest.raises(cleanup) as caught:
            archive.run()
        assert caught.value is archive.cleanup
    retired(archive)


def test_public_path_read_oserror_remains_unknown(archive):
    archive.primary = OSError('after native EOCD read')
    archive.cleanup = KeyboardInterrupt('after consumed EOCD close')
    assert archive.run() is None
    retired(archive)


def test_public_path_healthy_empty_zip_matches_bytes(archive):
    assert archive.run() == eocd.peek_eocd(archive.payload) == eocd.EocdSummary(0, 0)
    retired(archive)


def test_public_path_missing_zip_remains_unknown(archive):
    archive.path.unlink()
    assert archive.run() is None
    assert not archive.reads and not archive.streams and archive.closes == 0
