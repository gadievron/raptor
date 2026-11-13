"""Nonblocking orphan-sidecar retirement over owned inert files only."""
import builtins
import contextlib
import errno
import os
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from core.project import sessions
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_views import module_function_view


@pytest.fixture
def orphan(tmp_path, monkeypatch):
    fcntl = pytest.importorskip('fcntl')
    root = tmp_path / 'sessions.d'
    root.mkdir(mode=0o700)
    sidecar = root / f'{os.getpid()}.run.lock'
    sidecar.write_bytes(b'inert owned sidecar\n')
    state = SimpleNamespace(fd=None, identity=None, acquisition=None, unlock=None,
                            body=None, close_error=None, closes=0, acquired=0,
                            unlocked=0, swap=False, identities=[], sidecar=sidecar,
                            attempts=0, acquisition_once=False)
    private = ModuleType('fcntl')
    vars(private).update(vars(fcntl))

    def flock(fd, operation):
        if operation != fcntl.LOCK_UN:
            info = os.fstat(fd)
            current = sidecar.stat()
            assert (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino)
            state.fd, state.identity = fd, (info.st_dev, info.st_ino)
            state.attempts += 1
            fcntl.flock(fd, operation)
            state.acquired += 1
            state.identities.append(state.identity)
            if state.swap and state.acquired == 1:
                sidecar.rename(root / 'owned-retired')
                sidecar.write_bytes(b'inert replacement\n')
            if state.acquisition is not None:
                error = state.acquisition
                if state.acquisition_once:
                    state.acquisition = None
                raise error
        else:
            assert fd == state.fd
            fcntl.flock(fd, operation)
            state.unlocked += 1
            if state.unlock is not None:
                raise state.unlock

    private.flock = flock

    def import_owned(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == 'fcntl':
            return private
        return builtins.__import__(name, globals, locals, fromlist, level)

    class OwnedPath(type(Path())):
        def unlink(self, *args, **kwargs):
            result = super().unlink(*args, **kwargs)
            assert self == sidecar
            if state.body is not None:
                raise state.body
            return result

    def forbidden(*args, **kwargs):
        pytest.fail('orphan-only public sweep must not reach identity/credential/blocking paths')

    view = module_function_view(sessions, bindings={
        'SESSIONS_DIR': root, 'Path': OwnedPath,
        '_ledger_lock_nb': sessions._ledger_lock_nb.__wrapped__,
        '_ledger_lock': forbidden, '_parse_entry': forbidden,
        '_identity_matches': forbidden, 'resolve_session_pid': forbidden,
    }, import_hook=import_owned)
    view._ledger_lock_nb = contextlib.contextmanager(view._ledger_lock_nb)
    native_close = os.close

    def close(fd):
        assert fd == state.fd
        native_close(fd)
        state.closes += 1
        if state.close_error is not None:
            raise state.close_error

    patch_module_attribute(monkeypatch, view, 'os', 'close', close)
    state.run = lambda: view.read_sessions(prune=True)
    try:
        yield state
    finally:
        if state.fd is not None:
            try:
                info = os.fstat(state.fd)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                assert (info.st_dev, info.st_ino) == state.identity
                native_close(state.fd)


def retired(state, count=1):
    with pytest.raises(OSError) as caught:
        os.fstat(state.fd)
    assert caught.value.errno == errno.EBADF
    assert state.acquired == state.closes == count


def test_public_orphan_sweep_retires_interrupted_acquisition(orphan):
    orphan.acquisition = KeyboardInterrupt('after native nonblocking acquire')
    with pytest.raises(KeyboardInterrupt) as caught:
        orphan.run()
    assert caught.value is orphan.acquisition
    assert orphan.sidecar.exists()
    retired(orphan)


def test_public_orphan_sweep_retires_after_unlock_interruption(orphan):
    orphan.unlock = SystemExit('after native unlock')
    with pytest.raises(SystemExit) as caught:
        orphan.run()
    assert caught.value is orphan.unlock
    assert not orphan.sidecar.exists()
    retired(orphan)


def test_public_orphan_body_primary_survives_unlock_failure(orphan):
    orphan.body = KeyboardInterrupt('after native owned orphan unlink')
    orphan.unlock = MemoryError('after native unlock')
    with pytest.raises(KeyboardInterrupt) as caught:
        orphan.run()
    assert caught.value is orphan.body
    retired(orphan)


def test_public_healthy_orphan_sweep_retires_lock(orphan):
    assert orphan.run() == {}
    assert not orphan.sidecar.exists() and orphan.unlocked == 1
    retired(orphan)


def test_public_unlock_oserror_keeps_suppression(orphan):
    orphan.unlock = OSError('after native unlock')
    assert orphan.run() == {}
    retired(orphan)


def test_public_acquire_oserror_keeps_retry(orphan):
    orphan.acquisition = OSError('after first native acquire')
    orphan.acquisition_once = True
    assert orphan.run() == {}
    assert orphan.attempts == 2
    retired(orphan, 2)


def test_public_inode_change_retries_on_current_sidecar(orphan):
    orphan.swap = True
    assert orphan.run() == {}
    assert orphan.identities[0] != orphan.identities[1]
    retired(orphan, 2)


def test_public_true_contention_keeps_attempt_limit_and_sidecar(orphan):
    import fcntl
    holder = os.open(orphan.sidecar, os.O_WRONLY)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert orphan.run() == {}
        assert orphan.sidecar.exists()
        assert orphan.attempts == orphan.closes == 20 and orphan.acquired == 0
        with pytest.raises(OSError) as caught:
            os.fstat(orphan.fd)
        assert caught.value.errno == errno.EBADF
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)


@pytest.mark.parametrize('error_type', [OSError, MemoryError])
def test_public_fresh_consumed_close_failure_keeps_policy(orphan, error_type):
    orphan.close_error = error_type('after native descriptor retirement')
    if error_type is OSError:
        assert orphan.run() == {}
    else:
        with pytest.raises(MemoryError) as caught:
            orphan.run()
        assert caught.value is orphan.close_error
    retired(orphan)


def test_public_body_primary_survives_both_cleanup_failures(orphan):
    orphan.body = SystemExit('after native orphan unlink')
    orphan.unlock = MemoryError('after native unlock')
    orphan.close_error = KeyboardInterrupt('after native descriptor retirement')
    with pytest.raises(SystemExit) as caught:
        orphan.run()
    assert caught.value is orphan.body
    retired(orphan)
