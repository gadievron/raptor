"""Strict JSON readers retain operation errors while retiring owned resources."""
import errno
import os
from types import SimpleNamespace

import pytest

from core.json import bounded
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def reader(tmp_path, monkeypatch):
    path = tmp_path / 'owned.json'
    path.write_bytes(b'{"ok":true}')
    original_open, original_stat = os.open, os.fstat
    original_close, original_adopt = os.close, os.fdopen
    owners, streams, closed = [], [], []

    def install(phase=None, primary=None, stream_error=None, close_error=None):
        def opened(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            info = original_stat(fd)
            owners.append((fd, (info.st_dev, info.st_ino)))
            return fd

        def checked(fd):
            if phase == 'stat':
                raise primary
            return original_stat(fd)

        class Stream:
            def __init__(self, raw):
                self.raw = raw
            def __enter__(self):
                return self
            def read(self, size):
                if phase == 'read':
                    raise primary
                return self.raw.read(size)
            def __exit__(self, *args):
                self.raw.__exit__(*args)
                if stream_error is not None:
                    raise stream_error

        def adopt(fd, *args, **kwargs):
            if phase == 'adopt':
                raise primary
            stream = Stream(original_adopt(fd, *args, **kwargs))
            streams.append(stream)
            return stream

        def close(fd):
            original_close(fd)
            closed.append(fd)
            if close_error is not None:
                raise close_error

        for name, value in [('open', opened), ('fstat', checked), ('fdopen', adopt), ('close', close)]:
            patch_module_attribute(monkeypatch, bounded, 'os', name, value)

    yield SimpleNamespace(path=path, install=install, owners=owners, streams=streams, closed=closed)
    for stream in streams:
        stream.raw.close()
    for fd, identity in owners:
        try:
            info = original_stat(fd)
        except OSError:
            continue
        if (info.st_dev, info.st_ino) == identity:
            original_close(fd)


def assert_retired(reader):
    assert len(reader.owners) == 1
    fd = reader.owners[0][0]
    assert reader.closed == [fd]
    with pytest.raises(OSError) as caught:
        os.fstat(fd)
    assert caught.value.errno == errno.EBADF
    assert all(stream.raw.closed for stream in reader.streams)


@pytest.mark.parametrize('phase', ['stat', 'adopt', 'read'])
@pytest.mark.parametrize('error_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_primary_error_survives_cleanup(reader, phase, error_type):
    primary = error_type('owned failure')
    reader.install(phase, primary, OSError('stream cleanup'), RuntimeError('raw cleanup'))
    with pytest.raises(error_type) as caught:
        bounded.load_json_bounded(reader.path, max_bytes=16)
    assert caught.value is primary
    assert_retired(reader)


@pytest.mark.parametrize('cleanup', ['stream', 'raw'])
def test_cleanup_only_error_remains_visible(reader, cleanup):
    error = OSError('owned close failure')
    reader.install(stream_error=error if cleanup == 'stream' else None,
                   close_error=error if cleanup == 'raw' else None)
    with pytest.raises(OSError) as caught:
        bounded.load_json_bounded(reader.path, max_bytes=16)
    assert caught.value is error
    assert_retired(reader)


def test_initial_budget_refusal_precedes_adoption_and_cleanup(reader):
    reader.install(close_error=RuntimeError('raw cleanup'))
    with pytest.raises(bounded.JsonBudgetExceededError, match='exceeds'):
        bounded.load_json_bounded(reader.path, max_bytes=2)
    assert reader.streams == []
    assert_retired(reader)


def test_success_keeps_same_file_and_finite_json(reader):
    reader.install()
    assert bounded.load_json_bounded(reader.path, max_bytes=16) == {'ok': True}
    assert_retired(reader)
