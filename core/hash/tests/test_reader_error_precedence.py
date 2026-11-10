"""Hash readers retain cancellation and explicit native descriptor ownership."""

import errno
import hashlib
import os
from pathlib import Path

import pytest

import core.hash as hashes
from core.testing.module_views import scoped_function_imports


@pytest.fixture
def reader_case(tmp_path, monkeypatch):
    source = tmp_path / 'owned.bin'
    source.write_bytes(b'owned hash bytes\n')
    native_fdopen, native_close = os.fdopen, os.close
    streams, identities, closes = [], [], []

    def run(kind, primary=None, *, setup=False, skip=False,
            close_fails=True, raw_close_fails=False):
        def remember(fd):
            info = os.fstat(fd)
            identities.append((fd, info.st_dev, info.st_ino))

        class Reader:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

            def close(self):
                self.stream.close()
                if close_fails:
                    raise OSError('secondary stream close failure')

            def read(self, size):
                if primary is not None:
                    raise primary
                return self.stream.read(size)

        class OwnedPath(type(Path())):
            def open(self, *args, **kwargs):
                assert self == source
                stream = super().open(*args, **kwargs)
                remember(stream.fileno())
                streams.append(stream)
                return Reader(stream)

        def adopt(fd, *args, **kwargs):
            remember(fd)
            if setup:
                assert kwargs.get('closefd') is False
                raise primary
            stream = native_fdopen(fd, *args, **kwargs)
            streams.append(stream)
            return Reader(stream)

        def close(fd):
            # A size refusal never reached adoption, but still owns this FD.
            if skip:
                remember(fd)
            native_close(fd)
            closes.append(fd)
            if skip or raw_close_fails:
                raise OSError('best-effort raw close failure')

        if kind == 'file':
            monkeypatch.setattr(hashes, 'Path', OwnedPath)
            return hashes.sha256_file(source, chunk_size=4096)
        with scoped_function_imports(hashes, ('sha256_tree',), {'os': os}) as imports:
            imports.os.fdopen = adopt
            imports.os.close = close
            return hashes.sha256_tree(
                tmp_path, max_file_size=1 if skip else 1024, chunk_size=4096,
            )

    yield run, streams, identities, closes
    for stream in streams:
        stream.close()
    for fd, device, inode in identities:
        try:
            info = os.fstat(fd)
        except OSError:
            continue
        if (info.st_dev, info.st_ino) == (device, inode):
            native_close(fd)


def _retired(streams, identities):
    assert identities
    assert all(stream.closed for stream in streams)
    for fd, device, inode in identities:
        try:
            info = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            assert (info.st_dev, info.st_ino) != (device, inode)


@pytest.mark.parametrize('kind', ['file', 'tree'])
@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_read_cancellation_keeps_precedence(reader_case, kind, failure):
    run, streams, identities, _ = reader_case
    primary = failure('cancelled read')
    with pytest.raises(failure) as caught:
        run(kind, primary)
    assert caught.value is primary
    _retired(streams, identities)


@pytest.mark.parametrize('kind', ['file', 'tree'])
def test_stream_close_only_failure_remains_visible(reader_case, kind):
    run, streams, identities, _ = reader_case
    with pytest.raises(OSError, match='secondary stream close failure'):
        run(kind)
    _retired(streams, identities)


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_tree_adoption_failure_retires_untransferred_descriptor(reader_case, failure):
    run, streams, identities, closes = reader_case
    primary = failure('adoption failed')
    with pytest.raises(failure) as caught:
        run('tree', primary, setup=True)
    assert caught.value is primary
    assert streams == [] and closes == [identities[0][0]]
    _retired(streams, identities)


def test_tree_size_refusal_keeps_best_effort_raw_close(reader_case):
    run, streams, identities, closes = reader_case
    assert len(run('tree', skip=True)) == 64
    assert streams == [] and closes == [identities[0][0]]
    _retired(streams, identities)


def test_tree_adopted_raw_close_failure_remains_visible(reader_case):
    run, streams, identities, closes = reader_case
    with pytest.raises(OSError, match='raw close failure'):
        run('tree', close_fails=False, raw_close_fails=True)
    assert closes == [identities[0][0]]
    _retired(streams, identities)


def test_fileobj_keeps_its_callers_native_stream_open(tmp_path):
    path = tmp_path / 'borrowed'
    path.write_bytes(b'prefix-owned bytes')
    with path.open('rb') as stream:
        stream.seek(7)
        assert hashes.sha256_fileobj(stream, chunk_size=4096) == hashlib.sha256(b'owned bytes').hexdigest()
        assert stream.tell() == path.stat().st_size and not stream.closed
    assert stream.closed
