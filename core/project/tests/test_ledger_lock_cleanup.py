"""Retire only test-owned session sidecars through an actual public caller."""
import builtins
import contextlib
import errno
import os
from types import ModuleType, SimpleNamespace
from pathlib import Path

import pytest

from core.atomic_fs import fs_lock
from core.project import sessions
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_views import module_function_view


@pytest.fixture
def owned_registry(tmp_path, monkeypatch):
    fcntl = pytest.importorskip('fcntl')
    root = tmp_path / 'sessions.d'
    root.mkdir(mode=0o700)
    pid = os.getpid()
    entry = root / str(pid)
    ledger = root / f'{pid}.run'
    entry.write_bytes(b'inert owned entry, never parsed\n')
    ledger.write_bytes(b'inert owned ledger, never parsed\n')
    state = SimpleNamespace(fd=None, identity=None, acquisition=None, unlock=None,
                            closes=0, acquired=0, unlocked=0, root=root, ledger=ledger, body=None,
                            close_error=None, refuse=False, swap=False, identities=[],
                            expect_closed_body=False, pid=pid)
    private_fcntl = ModuleType('fcntl')
    vars(private_fcntl).update(vars(fcntl))
    private_fs = ModuleType('core.atomic_fs.fs_lock')
    vars(private_fs).update(vars(fs_lock))

    def acquire(fd, *args, **kwargs):
        info = os.fstat(fd)
        assert (info.st_dev, info.st_ino) == ((root / f'{pid}.run.lock').stat().st_dev,
                                              (root / f'{pid}.run.lock').stat().st_ino)
        state.fd = fd
        state.identity = (info.st_dev, info.st_ino)
        if state.refuse:
            holder = os.open(root / f'{pid}.run.lock', os.O_WRONLY)
            try:
                fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = fs_lock.acquire_flock_bounded(fd, *args, **(kwargs | {'deadline_s': 0}))
                assert result is False
            finally:
                fcntl.flock(holder, fcntl.LOCK_UN)
                os.close(holder)
            return False
        result = fs_lock.acquire_flock_bounded(fd, *args, **kwargs)
        assert result is True
        state.identities.append(state.identity)
        state.acquired += 1
        if state.swap and state.acquired == 1:
            (root / f'{pid}.run.lock').rename(root / 'owned-retired.lock')
            (root / f'{pid}.run.lock').write_bytes(b'')
        if state.acquisition is not None:
            raise state.acquisition
        return result

    def flock(fd, operation):
        assert fd == state.fd
        fcntl.flock(fd, operation)
        if operation == fcntl.LOCK_UN:
            state.unlocked += 1
            if state.unlock is not None:
                raise state.unlock

    private_fs.acquire_flock_bounded = acquire
    private_fcntl.flock = flock

    def import_owned(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == 'fcntl':
            return private_fcntl
        if level == 0 and name == 'core.atomic_fs.fs_lock':
            return private_fs
        return builtins.__import__(name, globals, locals, fromlist, level)

    class OwnedPath(type(Path())):
        def unlink(self, *args, **kwargs):
            if self == ledger and state.expect_closed_body:
                with pytest.raises(OSError) as caught:
                    os.fstat(state.fd)
                assert caught.value.errno == errno.EBADF
            result = super().unlink(*args, **kwargs)
            if self == ledger and state.body is not None:
                raise state.body
            return result

    view = module_function_view(sessions, bindings={
        'SESSIONS_DIR': root, 'Path': OwnedPath,
        '_ledger_lock': sessions._ledger_lock.__wrapped__,
        '_ledger_lock_nb': sessions._ledger_lock_nb.__wrapped__,
    }, import_hook=import_owned)
    view._ledger_lock = contextlib.contextmanager(view._ledger_lock)
    view._ledger_lock_nb = contextlib.contextmanager(view._ledger_lock_nb)
    native_close = os.close

    def close(fd):
        assert fd == state.fd
        native_close(fd)
        state.closes += 1
        if state.close_error is not None:
            raise state.close_error

    patch_module_attribute(monkeypatch, view, 'os', 'close', close)
    state.run = lambda: view.record_session(None, pid=pid)
    state.view = view
    try:
        yield state
    finally:
        if state.fd is not None:
            try:
                info = os.fstat(state.fd)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                # Fixture retires only a demonstrated still-owned leak; never
                # retry a consumed/reused descriptor.
                assert (info.st_dev, info.st_ino) == state.identity
                native_close(state.fd)


def assert_retired(state):
    with pytest.raises(OSError) as caught:
        os.fstat(state.fd)
    assert caught.value.errno == errno.EBADF
    assert state.acquired == state.closes == 1


def test_public_removal_retires_interrupted_acquisition(owned_registry):
    state = owned_registry
    state.acquisition = KeyboardInterrupt('after real bounded native acquire')
    with pytest.raises(KeyboardInterrupt) as caught:
        state.run()
    assert caught.value is state.acquisition
    assert state.ledger.read_bytes() == b'inert owned ledger, never parsed\n'
    assert_retired(state)


def test_public_removal_retires_after_unlock_interruption(owned_registry):
    state = owned_registry
    state.unlock = SystemExit('after real native unlock')
    with pytest.raises(SystemExit) as caught:
        state.run()
    assert caught.value is state.unlock
    assert state.unlocked == 1 and not state.ledger.exists()
    assert_retired(state)


def test_public_body_cancellation_survives_unlock_failure(owned_registry):
    state = owned_registry
    state.body = KeyboardInterrupt('after native owned ledger unlink')
    state.unlock = MemoryError('after real native unlock')
    with pytest.raises(KeyboardInterrupt) as caught:
        state.run()
    assert caught.value is state.body
    assert not state.ledger.exists()
    assert_retired(state)


def test_public_healthy_removal_keeps_native_policy(owned_registry):
    state = owned_registry
    assert state.run() == state.pid
    assert state.unlocked == 1 and not state.ledger.exists()
    assert_retired(state)


def test_public_unlock_oserror_keeps_suppression(owned_registry):
    state = owned_registry
    state.unlock = OSError('after real unlock')
    assert state.run() == state.pid
    assert_retired(state)


def test_public_acquire_oserror_closes_before_unlocked_body(owned_registry):
    state = owned_registry
    state.acquisition = OSError('after native acquisition')
    state.expect_closed_body = True
    assert state.run() == state.pid
    assert_retired(state)


def test_public_contention_expiry_closes_before_unlocked_body(owned_registry):
    state = owned_registry
    state.refuse = True
    state.expect_closed_body = True
    assert state.run() == state.pid
    assert state.acquired == 0 and state.closes == 1
    with pytest.raises(OSError) as caught:
        os.fstat(state.fd)
    assert caught.value.errno == errno.EBADF


def test_public_changed_inode_retries_after_retiring_old_fd(owned_registry):
    state = owned_registry
    state.swap = True
    assert state.run() == state.pid
    assert state.acquired == state.closes == 2
    assert state.identities[0] != state.identities[1]
    with pytest.raises(OSError) as caught:
        os.fstat(state.fd)
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('error_type', [OSError, MemoryError])
def test_public_fresh_consumed_close_failure_keeps_visibility(owned_registry, error_type):
    state = owned_registry
    state.close_error = error_type('after native descriptor close')
    if error_type is OSError:
        assert state.run() is None
    else:
        with pytest.raises(MemoryError) as caught:
            state.run()
        assert caught.value is state.close_error
    assert_retired(state)


def test_public_primary_survives_both_cleanup_failures(owned_registry):
    state = owned_registry
    state.body = SystemExit('after owned ledger unlink')
    state.unlock = MemoryError('after native unlock')
    state.close_error = KeyboardInterrupt('after native descriptor close')
    with pytest.raises(SystemExit) as caught:
        state.run()
    assert caught.value is state.body
    assert_retired(state)
