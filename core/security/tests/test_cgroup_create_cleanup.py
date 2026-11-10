"""Passive native ownership protocol; ordinary directories are not cgroups."""
import errno
import os

import pytest

from core.security import cgroup_scope
from core.testing.module_views import module_function_view


@pytest.fixture
def creation(tmp_path):
    records, calls = {}, []

    def create(*, primary=None, close_owner=None, close_error=None, rmdir_error=None):
        def track(fd, owner):
            info = os.fstat(fd)
            records[owner] = (fd, info.st_dev, info.st_ino)
            return fd

        def parent(path):
            assert path == tmp_path
            return track(os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC), 'parent')

        def mkdir(name, *, dir_fd):
            # Populate only owned regular fixture files, not kernel controls.
            os.mkdir(name, dir_fd=dir_fd)
            child = tmp_path / name
            (child / 'cgroup.events').write_text('populated 0\n')
            (child / 'cgroup.kill').touch()
            calls.append('mkdir')

        def opened(name, flags, *, dir_fd):
            owner = 'capability' if name == 'cgroup.kill' else 'node'
            calls.append('open-' + owner)
            return track(os.open(name, flags, dir_fd=dir_fd), owner)

        def read(fd, name):
            result = cgroup_scope._read(fd, name)
            calls.append('read')
            if primary is not None:
                raise primary
            return result

        def close(fd):
            owner = next(key for key, record in records.items() if record[0] == fd)
            os.close(fd)
            calls.append('close-' + owner)
            if owner == close_owner:
                raise close_error

        def rmdir(name, *, dir_fd):
            # Remove only the two known surrogate files in the owned leaf.
            child = tmp_path / name
            for path in (child / 'cgroup.events', child / 'cgroup.kill'):
                path.unlink()
            os.rmdir(name, dir_fd=dir_fd)
            calls.append('rmdir')
            if rmdir_error is not None:
                raise rmdir_error

        return module_function_view(cgroup_scope, bindings={
            'create_scope': cgroup_scope.Scope.create.__func__,
            '_open_directory': parent, '_read': read,
            'os': module_function_view(os, bindings={
                'mkdir': mkdir, 'open': opened, 'close': close, 'rmdir': rmdir,
            }),
        })

    yield create, tmp_path, records, calls
    live = []
    for owner, (fd, dev, ino) in records.items():
        try:
            info = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            if (info.st_dev, info.st_ino) == (dev, ino):
                live.append(owner)
                os.close(fd)
    if live:
        print('identity-verified live owners before fixture retirement:', live, 'calls:', calls)
        pytest.fail('creation retained directory ownership')


@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit, OSError],
                         ids=['interrupt', 'exit', 'io'])
@pytest.mark.parametrize('close_owner', ['node', 'parent'])
def test_creation_failure_retires_each_owner_and_preserves_primary(creation, error_type, close_owner):
    create, parent, records, calls = creation
    primary = error_type('owned post-read failure')
    private = create(primary=primary, close_owner=close_owner,
                     close_error=OSError('owned post-native-close failure'))
    with pytest.raises(error_type) as caught:
        private.create_scope(cgroup_scope.Scope, parent)
    assert caught.value is primary
    assert set(records) == {'node', 'parent'}
    assert calls == ['mkdir', 'open-node', 'read', 'close-node', 'rmdir', 'close-parent']


@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit], ids=['interrupt', 'exit'])
def test_leaf_cleanup_cancellation_keeps_primary_and_retires_parent(creation, error_type):
    create, parent, records, calls = creation
    primary = OSError('owned admission read failure')
    private = create(primary=primary, rmdir_error=error_type('owned after-rmdir failure'))
    with pytest.raises(OSError) as caught:
        private.create_scope(cgroup_scope.Scope, parent)
    assert caught.value is primary
    assert set(records) == {'node', 'parent'}
    assert calls[-2:] == ['rmdir', 'close-parent']


def test_capability_close_failure_still_retires_directory_owners(creation):
    create, parent, records, calls = creation
    primary = OSError('owned capability close failure')
    private = create(close_owner='capability', close_error=primary)
    with pytest.raises(OSError) as caught:
        private.create_scope(cgroup_scope.Scope, parent)
    assert caught.value is primary
    assert set(records) == {'parent', 'node', 'capability'}
    assert calls[-4:] == ['close-capability', 'close-node', 'rmdir', 'close-parent']


def test_constructor_failure_keeps_native_capability_check_and_cleanup(creation):
    create, parent, records, calls = creation
    primary = KeyboardInterrupt('owned constructor cancellation')

    def constructor(path, node, parent_fd):
        assert os.fstat(node).st_ino == records['node'][2]
        assert parent_fd == records['parent'][0] and path.parent == parent
        calls.append('construct')
        raise primary

    with pytest.raises(KeyboardInterrupt) as caught:
        create().create_scope(constructor, parent)
    assert caught.value is primary
    assert calls[-4:] == ['construct', 'close-node', 'rmdir', 'close-parent']


def test_success_transfers_owned_directory_descriptors(creation):
    create, parent, records, calls = creation
    scope = create().create_scope(cgroup_scope.Scope, parent)
    try:
        assert scope.parent == records['parent'][0] and scope.node == records['node'][0]
        assert scope.identity == list(records['node'][1:])
        assert not os.get_inheritable(scope.node) and not os.get_inheritable(scope.parent)
        assert calls == ['mkdir', 'open-node', 'read', 'open-capability', 'close-capability']
    finally:
        scope.close()
