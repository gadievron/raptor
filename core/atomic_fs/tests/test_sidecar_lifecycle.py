"""Sidecar ownership and descriptor cleanup survive faults and cancellation."""
import errno
import os

import pytest

from core.atomic_fs import fs_lock as locks
from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(not locks._HAS_FCNTL, reason='requires flock')


@pytest.fixture
def opened(monkeypatch):
    records = []
    original = os.open
    def tracked(*args, **kwargs):
        fd = original(*args, **kwargs)
        records.append(fd)
        return fd
    patch_module_attribute(monkeypatch, locks, 'os', 'open', tracked)
    return records


def closed(records):
    assert records
    for fd in records:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('close_failure', [None, OSError, KeyboardInterrupt], ids=['close-ok', 'close-io', 'close-cancel'])
def test_failed_validation_closes_before_fallback_and_preserves_errors(tmp_path, monkeypatch, opened, required, failure, close_failure):
    original = os.close
    def invalid(*args):
        raise failure('validation failed')
    def close(fd):
        original(fd)
        if close_failure:
            raise close_failure('close failed')
    monkeypatch.setattr(locks, 'validate_lock_fd', invalid)
    patch_module_attribute(monkeypatch, locks, 'os', 'close', close)
    entered = []
    def run():
        with locks.sidecar_flock(tmp_path / 'state.lock', required=required):
            closed(opened)
            entered.append(True)
    if failure is OSError and not required:
        if close_failure is KeyboardInterrupt:
            with pytest.raises(KeyboardInterrupt, match='close failed'):
                run()
            assert not entered
        else:
            run()
            assert entered == [True]
    else:
        with pytest.raises(failure, match='validation failed'):
            run()
        assert not entered
    closed(opened)


@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
@pytest.mark.parametrize('failure', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('phase', ['unlock', 'close', 'both'])
def test_body_error_keeps_precedence_and_descriptor_is_closed(tmp_path, monkeypatch, opened, required, failure, cleanup_failure, phase):
    original_flock, original_close = locks.fcntl.flock, os.close
    def flock(fd, operation):
        result = original_flock(fd, operation)
        if operation == locks.fcntl.LOCK_UN:
            raise cleanup_failure('unlock failed')
        return result
    def close(fd):
        original_close(fd)
        raise cleanup_failure('close failed')
    if phase in ('unlock', 'both'):
        patch_module_attribute(monkeypatch, locks, 'fcntl', 'flock', flock)
    if phase in ('close', 'both'):
        patch_module_attribute(monkeypatch, locks, 'os', 'close', close)
    with pytest.raises(failure, match='body failed'):
        with locks.sidecar_flock(tmp_path / 'state.lock', required=required):
            raise failure('body failed')
    closed(opened)


@pytest.mark.parametrize('cleanup_failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('phase', ['unlock', 'close', 'both'])
def test_successful_write_is_not_relabelled_as_io_failure_but_new_cancel_propagates(tmp_path, monkeypatch, opened, cleanup_failure, phase):
    original_flock, original_close = locks.fcntl.flock, os.close
    def flock(fd, operation):
        result = original_flock(fd, operation)
        if operation == locks.fcntl.LOCK_UN:
            raise cleanup_failure('unlock failed')
        return result
    def close(fd):
        original_close(fd)
        raise cleanup_failure('close failed')
    if phase in ('unlock', 'both'):
        patch_module_attribute(monkeypatch, locks, 'fcntl', 'flock', flock)
    if phase in ('close', 'both'):
        patch_module_attribute(monkeypatch, locks, 'os', 'close', close)
    data = tmp_path / 'data'
    def write():
        with locks.sidecar_flock(tmp_path / 'state.lock', required=True):
            data.write_text('committed')
    if cleanup_failure is OSError:
        write()
    else:
        with pytest.raises(cleanup_failure):
            write()
    assert data.read_text() == 'committed'
    closed(opened)


@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
@pytest.mark.parametrize('replacement', ['new-file', 'missing'])
def test_replaced_path_is_reacquired_before_stamping_or_yield(tmp_path, monkeypatch, opened, required, replacement):
    lock = tmp_path / 'state.lock'
    lock.write_text('111\n')
    retired = tmp_path / 'retired.lock'
    original = locks.acquire_flock_bounded
    calls = []
    def acquire(fd, path, **kwargs):
        result = original(fd, path, **kwargs)
        calls.append(fd)
        if len(calls) == 1:
            lock.rename(retired)
            if replacement == 'new-file':
                lock.write_text('222\n')
        return result
    monkeypatch.setattr(locks, 'acquire_flock_bounded', acquire)
    with locks.sidecar_flock(lock, required=required):
        assert len(calls) == 2
        assert retired.read_text() == '111\n'
        assert lock.read_text() == f'{os.getpid()}\n'
        contender = os.open(lock, os.O_WRONLY)
        try:
            with pytest.raises(BlockingIOError):
                locks.fcntl.flock(contender, locks.fcntl.LOCK_EX | locks.fcntl.LOCK_NB)
        finally:
            os.close(contender)
    closed(opened)


@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
def test_repeated_replacements_are_bounded_and_share_one_wait_budget(tmp_path, monkeypatch, opened, required):
    lock = tmp_path / 'state.lock'
    clock, budgets = [0.0], []
    def acquire(fd, path, **kwargs):
        budgets.append(kwargs['deadline_s'])
        locks.fcntl.flock(fd, locks.fcntl.LOCK_EX | locks.fcntl.LOCK_NB)
        clock[0] += 0.4
        path.unlink()
        path.write_text('untouched')
        return True
    patch_module_attribute(monkeypatch, locks, 'time', 'monotonic', lambda: clock[0])
    monkeypatch.setattr(locks, 'acquire_flock_bounded', acquire)
    entered = []
    def run():
        with locks.sidecar_flock(lock, required=required, deadline_s=1):
            closed(opened)
            entered.append(True)
    if required:
        with pytest.raises(OSError, match='did not stabilize') as error:
            run()
        assert error.value.errno == errno.EAGAIN
    else:
        run()
    assert entered == ([] if required else [True])
    assert budgets == pytest.approx([1, 0.6, 0.2])
    assert lock.read_text() == 'untouched'
    closed(opened)


@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
@pytest.mark.parametrize('late', [False, True], ids=['preexisting', 'after-acquire'])
def test_hardlinked_sidecar_is_never_stamped(tmp_path, monkeypatch, required, late):
    lock, other = tmp_path / 'state.lock', tmp_path / 'other'
    lock.write_text('original data')
    if late:
        original = locks.acquire_flock_bounded
        def acquire(fd, path, **kwargs):
            result = original(fd, path, **kwargs)
            os.link(lock, other)
            return result
        monkeypatch.setattr(locks, 'acquire_flock_bounded', acquire)
    else:
        os.link(lock, other)
    if required:
        with pytest.raises(OSError, match='hardlinked'):
            with locks.sidecar_flock(lock, required=True):
                pytest.fail('required mutation admitted')
    else:
        with locks.sidecar_flock(lock):
            pass
    assert lock.read_text() == other.read_text() == 'original data'


@pytest.mark.parametrize('required', [False, True], ids=['best-effort', 'required'])
@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_failed_acquisition_closes_held_descriptor_without_entering(tmp_path, monkeypatch, opened, required, failure):
    lock = tmp_path / 'state.lock'
    lock.write_text('111\n')
    def acquire(fd, path, **kwargs):
        locks.fcntl.flock(fd, locks.fcntl.LOCK_EX | locks.fcntl.LOCK_NB)
        raise failure('acquisition failed')
    monkeypatch.setattr(locks, 'acquire_flock_bounded', acquire)
    with pytest.raises(failure, match='acquisition failed'):
        with locks.sidecar_flock(lock, required=required):
            pytest.fail('failed acquisition entered body')
    closed(opened)
    assert lock.read_text() == '111\n'
    contender = os.open(lock, os.O_WRONLY)
    try:
        locks.fcntl.flock(contender, locks.fcntl.LOCK_EX | locks.fcntl.LOCK_NB)
    finally:
        os.close(contender)
