"""Passive reader error precedence; no cgroup enforcement claim."""
from contextlib import ExitStack
import errno
import os

import pytest

from core.sandbox import job_budget
from core.security import cgroup_scope
from core.testing.module_views import module_function_view


@pytest.fixture
def reader(tmp_path):
    records = []
    with ExitStack() as owners:
        node = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        owners.callback(os.close, node)
        parent = os.open(tmp_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        owners.callback(os.close, parent)
        scope = cgroup_scope.Scope(tmp_path, node, parent)

        def create(*, content=b'17\n', read_error=None, close_error=None):
            for name in ('control', 'memory.current', 'memory.peak', 'memory.events',
                         'cpu.stat', 'pids.current', 'pids.peak'):
                (tmp_path / name).write_bytes(content)

            def opened(*args, **kwargs):
                descriptor = os.open(*args, **kwargs)
                info = os.fstat(descriptor)
                records.append((descriptor, info.st_dev, info.st_ino))
                return descriptor

            def read(descriptor, limit):
                result = os.read(descriptor, limit)
                if read_error is not None:
                    raise read_error
                return result

            def close(descriptor):
                os.close(descriptor)
                if close_error is not None:
                    raise close_error

            return module_function_view(cgroup_scope, bindings={
                'os': module_function_view(os, bindings={
                    'open': opened, 'read': read, 'close': close,
                }),
            })

        yield scope, create, records
        for descriptor, device, inode in records:
            try:
                info = os.fstat(descriptor)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                if (info.st_dev, info.st_ino) == (device, inode):
                    os.close(descriptor)
                    pytest.fail('reader left its owned descriptor live')


@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit], ids=['interrupt', 'exit'])
def test_read_cancellation_survives_close_io(reader, error_type):
    scope, create, records = reader
    failure = error_type('owned read cancellation')
    private = create(read_error=failure, close_error=OSError('owned after-close IO'))
    with pytest.raises(error_type) as caught:
        private._read(scope.node, 'control')
    assert caught.value is failure
    assert len(records) == 1


def test_snapshot_does_not_convert_read_cancellation_to_unavailable(reader):
    scope, create, records = reader
    failure = KeyboardInterrupt('owned counter read cancellation')
    controls = create(read_error=failure, close_error=OSError('owned after-close IO'))
    private = module_function_view(job_budget, bindings={'cgroup_scope': controls})
    with pytest.raises(KeyboardInterrupt) as caught:
        private._snapshot(scope)
    assert caught.value is failure
    assert len(records) == 1


@pytest.mark.parametrize('content, error_type', [
    (b'\xff', UnicodeDecodeError), (b'x' * 16385, ValueError),
], ids=['non-ascii', 'oversized'])
def test_validation_error_survives_close_cancellation(reader, content, error_type):
    scope, create, records = reader
    private = create(content=content, close_error=KeyboardInterrupt('owned after-close cancellation'))
    with pytest.raises(error_type):
        private._read(scope.node, 'control')
    assert len(records) == 1


@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt], ids=['io', 'interrupt'])
def test_fresh_close_error_remains_visible_after_success(reader, error_type):
    scope, create, records = reader
    failure = error_type('owned after-close failure')
    private = create(close_error=failure)
    with pytest.raises(error_type) as caught:
        private._read(scope.node, 'control')
    assert caught.value is failure
    assert len(records) == 1


def test_success_preserves_exact_ascii_content(reader):
    scope, create, records = reader
    private = create(content=b'populated 0\nfrozen 0\n')
    assert private._read(scope.node, 'control') == 'populated 0\nfrozen 0\n'
    assert len(records) == 1
