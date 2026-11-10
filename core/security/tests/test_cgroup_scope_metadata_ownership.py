"""Read-only trusted parent ownership before cgroup directory creation."""
import errno
import os
import sys

import pytest

from core.security import cgroup_scope
from core.testing.module_views import module_function_view


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='actual Linux trusted cgroup mount')


@pytest.fixture
def creation():
    records, calls = [], []

    def parent(path):
        try:
            descriptor = cgroup_scope._open_directory(path)
        except (OSError, ValueError) as error:
            pytest.skip('actual trusted cgroup mount unavailable: ' + type(error).__name__)
        info = os.fstat(descriptor)
        records.append((descriptor, info.st_dev, info.st_ino))
        calls.append('parent')
        return descriptor

    def create(*, token_error=None):
        refusal = OSError('owned pre-mkdir refusal; no cgroup write')

        def token_hex(size):
            assert size == 16
            calls.append('token')
            if token_error is not None:
                raise token_error
            return cgroup_scope.secrets.token_hex(size)

        def mkdir(name, *, dir_fd):
            calls.append('mkdir-boundary')
            assert records and dir_fd == records[0][0]
            info = os.fstat(dir_fd)
            assert (info.st_dev, info.st_ino) == records[0][1:]
            assert name.startswith('raptor-') and len(name) == 39
            assert all(char in '0123456789abcdef' for char in name[7:])
            raise refusal

        private = module_function_view(cgroup_scope, bindings={
            'create_scope': cgroup_scope.Scope.create.__func__,
            '_open_directory': parent,
            'secrets': module_function_view(cgroup_scope.secrets, bindings={'token_hex': token_hex}),
            'os': module_function_view(os, bindings={'mkdir': mkdir}),
        })
        return private, refusal

    try:
        yield create, records, calls
    finally:
        for descriptor, device, inode in records:
            try:
                info = os.fstat(descriptor)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == (device, inode):
                os.close(descriptor)


def assert_retired(records):
    assert len(records) == 1, 'actual trusted parent acquisition was not reached'
    with pytest.raises(OSError) as caught:
        os.fstat(records[0][0])
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt, SystemExit, MemoryError],
                         ids=['io', 'interrupt', 'exit', 'memory'])
def test_metadata_failure_retires_trusted_parent(creation, error_type):
    create, records, calls = creation
    failure = error_type('owned token metadata failure')
    private, _ = create(token_error=failure)
    with pytest.raises(error_type) as caught:
        private.create_scope(cgroup_scope.Scope, cgroup_scope.CGROUP_ROOT)
    assert calls == ['parent', 'token']
    assert_retired(records)
    assert caught.value is failure


def test_successful_metadata_reaches_creation_with_owned_parent(creation):
    create, records, calls = creation
    private, refusal = create()
    with pytest.raises(OSError) as caught:
        private.create_scope(cgroup_scope.Scope, cgroup_scope.CGROUP_ROOT)
    assert calls == ['parent', 'token', 'mkdir-boundary']
    assert_retired(records)
    assert caught.value is refusal
