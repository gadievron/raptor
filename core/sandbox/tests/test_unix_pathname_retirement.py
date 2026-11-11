"""Pathname lookup retires owned descriptors independently of close errors."""
import errno
import os
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import _unix_scope as scope
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux Unix-scope backend')


@pytest.fixture
def pathname_lookup(tmp_path):
    target = tmp_path / 'owned-file'
    target.write_bytes(b'owned')
    records = {}
    events = []

    def exercise(primary, secondary):
        root_fd, target_fd = records['root'][0], records['target'][0]

        def opened(path, flags):
            assert path == '/proc/123/root'
            assert flags == os.O_PATH | os.O_CLOEXEC
            return root_fd

        def resolve(fd, path, flags, resolve_flags):
            assert fd == root_fd and path == b'owned-file'
            assert flags == os.O_PATH | os.O_CLOEXEC
            assert resolve_flags == (scope._RESOLVE_IN_ROOT | scope._RESOLVE_NO_SYMLINKS
                                     | scope._RESOLVE_NO_MAGICLINKS)
            return target_fd

        def checked_stat(fd):
            assert fd == target_fd
            if primary is not None:
                raise primary
            return os.fstat(fd)

        def close(fd):
            name = next(name for name, record in records.items() if record[0] == fd)
            assert name not in events, 'owned descriptor closed twice'
            info = os.fstat(fd)
            assert (info.st_dev, info.st_ino) == records[name][1:]
            os.close(fd)
            events.append(name)
            if name == 'target' and secondary is not None:
                raise secondary

        private_os = module_function_view(os, bindings={
            'open': opened, 'fstat': checked_stat, 'close': close,
        })
        private = module_function_view(scope, bindings={
            '_lookup': scope.UnixScopeSupervisor._connect_pathname,
            'os': private_os, '_openat2': resolve,
        })
        return private._lookup(SimpleNamespace(), -1, 123, b'/owned-file')

    try:
        for name, path in [('root', tmp_path), ('target', target)]:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            records[name] = (fd, None, None)
            info = os.fstat(fd)
            records[name] = (fd, info.st_dev, info.st_ino)
        yield exercise, records, events
    finally:
        for fd, device, inode in records.values():
            try:
                info = os.fstat(fd)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                if device is None or (info.st_dev, info.st_ino) == (device, inode):
                    os.close(fd)


@pytest.mark.parametrize('primary_type', [None, ValueError, KeyboardInterrupt],
                         ids=['return', 'error', 'interrupt'])
@pytest.mark.parametrize('secondary_type', [OSError, RuntimeError, KeyboardInterrupt],
                         ids=['close-io', 'close-error', 'close-interrupt'])
def test_pathname_cleanup_attempts_both_owners(pathname_lookup, primary_type, secondary_type):
    exercise, records, events = pathname_lookup
    primary = primary_type('owned lookup failure') if primary_type else None
    secondary = secondary_type('owned consumed close failure')
    caught = None
    try:
        exercise(primary, secondary)
    except BaseException as error:
        caught = error
    assert events == ['target', 'root']
    assert caught is (primary if primary is not None else secondary)
    for fd, _, _ in records.values():
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF


def test_non_socket_refusal_retires_both_owners(pathname_lookup):
    exercise, _, events = pathname_lookup
    assert exercise(None, None) == (-errno.ECONNREFUSED, 0)
    assert events == ['target', 'root']
