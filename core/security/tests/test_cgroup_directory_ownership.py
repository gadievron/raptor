"""Read-only trusted directory walking owns each child before parent retirement."""

import errno
import fcntl
import os
import secrets
import stat
import sys
from types import SimpleNamespace

import pytest

from core.security import cgroup_scope
from core.testing.module_views import module_function_view


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux trusted cgroup mount')


@pytest.fixture
def trusted_mount():
    try:
        descriptor = cgroup_scope._open_directory(cgroup_scope.CGROUP_ROOT)
    except (OSError, ValueError) as error:
        pytest.skip('actual trusted cgroup mount unavailable: ' + type(error).__name__)
    os.close(descriptor)
    return cgroup_scope.CGROUP_ROOT


@pytest.fixture
def walker(trusted_mount):
    records = []

    def create(*, release_number=None, primary=None, cleanup_error=None):
        closed, open_errors = [], []

        def open_directory(*args, **kwargs):
            try:
                descriptor = os.open(*args, **kwargs)
            except OSError as error:
                open_errors.append(error)
                raise
            info = os.fstat(descriptor)
            records.append((descriptor, info.st_dev, info.st_ino))
            return descriptor

        def close(descriptor):
            os.close(descriptor)
            closed.append(descriptor)
            if release_number == len(closed):
                raise primary
            if (open_errors or primary is not None) and cleanup_error is not None:
                raise cleanup_error

        private = module_function_view(cgroup_scope, bindings={
            'os': module_function_view(os, bindings={'open': open_directory, 'close': close}),
        })
        return SimpleNamespace(open=private._open_directory, records=records,
                               closed=closed, open_errors=open_errors)

    try:
        yield create
    finally:
        for descriptor, device, inode in records:
            try:
                info = os.fstat(descriptor)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == (device, inode):
                os.close(descriptor)


def assert_retired(records):
    live = []
    for descriptor, device, inode in records:
        try:
            info = os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            if (info.st_dev, info.st_ino) == (device, inode):
                live.append((descriptor, inode))
    assert not live, f'directory walk left native handles live: {live}'


@pytest.mark.parametrize('release_number', [1, 2, 3], ids=['first', 'middle', 'last'])
@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt], ids=['io', 'interrupt'])
def test_parent_close_failure_retires_the_opened_child(trusted_mount, walker,
                                                       release_number, error_type):
    failure = error_type('owned after-close parent failure')
    view = walker(release_number=release_number, primary=failure)
    caught = None
    try:
        view.open(trusted_mount)
    except BaseException as error:
        caught = error
    assert len(view.records) == release_number + 1, 'intended handoff was not reached'
    assert_retired(view.records)
    assert caught is failure


def test_success_returns_one_readonly_caller_owned_directory(trusted_mount, walker):
    view = walker()
    descriptor = view.open(trusted_mount)
    info = os.fstat(descriptor)
    expected = os.stat(trusted_mount)
    assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
    assert stat.S_ISDIR(info.st_mode)
    assert fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
    assert not os.get_inheritable(descriptor)
    os.close(descriptor)
    assert_retired(view.records)


def test_parent_failure_survives_child_cleanup_cancellation(trusted_mount, walker):
    failure = OSError('owned parent close failure')
    view = walker(release_number=1, primary=failure,
                  cleanup_error=KeyboardInterrupt('owned child cleanup cancellation'))
    with pytest.raises(OSError) as caught:
        view.open(trusted_mount)
    assert len(view.records) == 2
    assert_retired(view.records)
    assert caught.value is failure


def test_native_missing_child_error_survives_cleanup_cancellation(trusted_mount, walker):
    view = walker(cleanup_error=KeyboardInterrupt('owned cleanup cancellation'))
    caught = None
    try:
        view.open(trusted_mount / ('raptor-missing-' + secrets.token_hex(16)))
    except BaseException as error:
        caught = error
    assert len(view.open_errors) == 1 and isinstance(view.open_errors[0], FileNotFoundError)
    assert_retired(view.records)
    assert caught is view.open_errors[0]
