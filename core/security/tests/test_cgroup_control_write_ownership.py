"""Owned regular-file writer faults; no actual cgroup membership or kill."""
from contextlib import ExitStack
import errno
import os
from types import MethodType

import pytest

from core.sandbox import job_budget
from core.security import cgroup_scope
from core.testing.module_views import module_function_view


@pytest.fixture
def writer(tmp_path):
    records = []
    with ExitStack() as owners:
        node = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        owners.callback(os.close, node)
        parent = os.open(tmp_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        owners.callback(os.close, parent)
        scope = cgroup_scope.Scope(tmp_path, node, parent)
        for name in ('control', 'cgroup.procs'):
            (tmp_path / name).touch()

        def create(*, write_error=None, close_error=None, short=False):
            def opened(*args, **kwargs):
                descriptor = os.open(*args, **kwargs)
                info = os.fstat(descriptor)
                records.append((descriptor, info.st_dev, info.st_ino))
                return descriptor

            def write(descriptor, data):
                result = os.write(descriptor, data[:-1] if short else data)
                if write_error is not None:
                    raise write_error
                return result

            def close(descriptor):
                os.close(descriptor)
                if close_error is not None:
                    raise close_error

            return module_function_view(cgroup_scope, bindings={
                'attach_scope': cgroup_scope.Scope.attach,
                'os': module_function_view(os, bindings={
                    'open': opened, 'write': write, 'close': close,
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
                    pytest.fail('writer left its owned regular-file descriptor live')


@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit], ids=['interrupt', 'exit'])
def test_job_admission_preserves_writer_cancellation(writer, error_type):
    scope, create, records = writer
    failure = error_type('owned regular-file write cancellation')
    controls = create(write_error=failure, close_error=OSError('owned after-close IO'))
    scope.attach = MethodType(controls.attach_scope, scope)
    job = job_budget.Job(None, namespace_backend=False)
    job.scope = scope
    with pytest.raises(error_type) as caught:
        job.attach(123)
    assert caught.value is failure
    assert not job.attached and job.record['status'] == 'not_requested'
    assert (scope.path / 'cgroup.procs').read_bytes() == b'123'
    assert len(records) == 1


def test_short_write_refusal_survives_close_cancellation(writer):
    scope, create, records = writer
    private = create(short=True, close_error=KeyboardInterrupt('owned after-close cancellation'))
    with pytest.raises(OSError) as caught:
        private._write(scope.node, 'control', '123')
    assert caught.value.errno == errno.EIO
    assert (scope.path / 'control').read_bytes() == b'12'
    assert len(records) == 1


def test_ascii_refusal_survives_close_cancellation(writer):
    scope, create, records = writer
    private = create(close_error=KeyboardInterrupt('owned after-close cancellation'))
    with pytest.raises(UnicodeEncodeError):
        private._write(scope.node, 'control', '\u00e9')
    assert (scope.path / 'control').read_bytes() == b''
    assert len(records) == 1


def test_primary_write_io_survives_close_cancellation(writer):
    scope, create, records = writer
    failure = OSError('owned after-write IO')
    private = create(write_error=failure, close_error=KeyboardInterrupt('owned after-close cancellation'))
    with pytest.raises(OSError) as caught:
        private._write(scope.node, 'control', '123')
    assert caught.value is failure
    assert (scope.path / 'control').read_bytes() == b'123'
    assert len(records) == 1


@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt], ids=['io', 'interrupt'])
def test_fresh_close_error_remains_visible_after_write(writer, error_type):
    scope, create, records = writer
    failure = error_type('owned after-close failure')
    private = create(close_error=failure)
    with pytest.raises(error_type) as caught:
        private._write(scope.node, 'control', '123')
    assert caught.value is failure
    assert (scope.path / 'control').read_bytes() == b'123'
    assert len(records) == 1


def test_success_preserves_exact_ascii_write(writer):
    scope, create, records = writer
    private = create()
    assert private._write(scope.node, 'control', '123\n') is None
    assert (scope.path / 'control').read_bytes() == b'123\n'
    assert len(records) == 1
