"""Duplicated descriptor ownership begins before the source owner is closed."""
import errno
import io
import os
import socket
import struct
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import _unix_scope as scope
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux Unix-scope backend')


@pytest.fixture
def owned_handoff(tmp_path):
    records, events, dispatched = {}, [], []

    def exercise(primary, source_error, duplicate_error):
        source_fd, duplicate_fd = records['source'][0], records['duplicate'][0]

        def memory(path, mode, *, buffering):
            assert path == '/proc/123/mem' and mode == 'rb' and buffering == 0
            return io.BytesIO(b'\0' + struct.pack('=H', socket.AF_INET))

        def pidfd(pid):
            assert pid == 123
            return source_fd

        def duplicate(fd, target_fd):
            assert fd == source_fd and target_fd == 77
            if primary is not None:
                raise primary
            return duplicate_fd

        def close(fd):
            name = next(name for name, record in records.items() if record[0] == fd)
            assert name not in events, 'owned descriptor closed twice'
            info = os.fstat(fd)
            assert (info.st_dev, info.st_ino) == records[name][1:]
            os.close(fd)
            events.append(name)
            error = source_error if name == 'source' else duplicate_error
            if error is not None:
                raise error

        def dispatch(fd, address, family, pid, *, nid):
            assert fd == duplicate_fd and address == struct.pack('=H', socket.AF_INET)
            assert family == socket.AF_INET and pid == 123 and nid == 1
            dispatched.append(fd)
            return 0, 0

        private = module_function_view(scope, bindings={
            '_decide': scope.UnixScopeSupervisor._decide_and_execute,
            'os': module_function_view(os, bindings={'close': close}),
            'open': memory, '_pidfd_open_task': pidfd, '_pidfd_getfd': duplicate,
        })
        owner = SimpleNamespace(_connect_nr=None, _id_valid=lambda nid: nid == 1,
                                _connect_inet_policied=dispatch)
        return private._decide(owner, 1, 123, 0, 77, 1, 2)

    try:
        for name in ('source', 'duplicate'):
            path = tmp_path / name
            path.write_bytes(b'owned')
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            records[name] = (fd, None, None)
            info = os.fstat(fd)
            records[name] = (fd, info.st_dev, info.st_ino)
        yield exercise, records, events, dispatched
    finally:
        for fd, device, inode in records.values():
            try:
                info = os.fstat(fd)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                if device is None or (info.st_dev, info.st_ino) == (device, inode):
                    os.close(fd)


@pytest.mark.parametrize('source_error_type', [OSError, RuntimeError, KeyboardInterrupt],
                         ids=['source-io', 'source-error', 'source-interrupt'])
@pytest.mark.parametrize('duplicate_error_type', [None, KeyboardInterrupt],
                         ids=['duplicate-closed', 'duplicate-interrupt'])
def test_source_cleanup_failure_retires_acquired_duplicate(
        owned_handoff, source_error_type, duplicate_error_type):
    exercise, records, events, dispatched = owned_handoff
    source_error = source_error_type('owned consumed source close failure')
    duplicate_error = duplicate_error_type('owned consumed duplicate close failure') if duplicate_error_type else None
    caught = None
    try:
        exercise(None, source_error, duplicate_error)
    except BaseException as error:
        caught = error
    assert events == ['source', 'duplicate']
    assert caught is source_error
    assert dispatched == []
    for fd, _, _ in records.values():
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF


@pytest.mark.parametrize('primary_type', [ValueError, KeyboardInterrupt], ids=['error', 'interrupt'])
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt], ids=['close-io', 'close-interrupt'])
def test_acquisition_failure_survives_source_cleanup(owned_handoff, primary_type, cleanup_type):
    exercise, _, events, dispatched = owned_handoff
    primary = primary_type('owned acquisition failure')
    caught = None
    try:
        exercise(primary, cleanup_type('owned consumed source close failure'), None)
    except BaseException as error:
        caught = error
    assert caught is primary
    assert events == ['source']
    assert dispatched == []


def test_successful_handoff_keeps_dispatch_and_retires_both_owners(owned_handoff):
    exercise, records, events, dispatched = owned_handoff
    assert exercise(None, None, None) == (0, 0)
    assert events == ['source', 'duplicate']
    assert dispatched == [records['duplicate'][0]]
