"""Reporting lock descriptors remain owned through parent retirement."""

import errno
import fcntl
import os
from types import SimpleNamespace

import pytest

from core.reporting import writer


@pytest.fixture
def lock_state(tmp_path, monkeypatch):
    directory = tmp_path / 'report'
    directory.mkdir()
    state = {'directory': directory, 'parent_error': None, 'child_error': None,
             'parent_faulted': False, 'recycle_parent': False, 'calls': [], 'live': set()}
    original = writer.open_dir_beneath

    def parent(*args, **kwargs):
        fd = original(*args, **kwargs)
        state['parent'] = fd
        state['live'].add(fd)
        return fd

    def open_child(*args, **kwargs):
        try:
            fd = os.open(*args, **kwargs)
        except OSError as exc:
            state['open_error'] = exc
            raise
        state['child'] = fd
        state['live'].add(fd)
        return fd

    def close(fd):
        state['calls'].append(fd)
        os.close(fd)
        state['live'].remove(fd)
        if fd == state['parent'] and state['parent_error'] is not None and not state['parent_faulted']:
            state['parent_faulted'] = True
            if state['recycle_parent']:
                os.dup2(state['guard'], fd)
                state['live'].add(fd)
            raise state['parent_error']
        if fd == state.get('child') and state['child_error'] is not None:
            raise state['child_error']

    monkeypatch.setattr(writer, 'open_dir_beneath', parent)
    monkeypatch.setattr(writer, 'os', SimpleNamespace(
        open=open_child, close=close, fstat=os.fstat, O_CREAT=os.O_CREAT,
        O_RDWR=os.O_RDWR, O_NOFOLLOW=os.O_NOFOLLOW, O_NONBLOCK=os.O_NONBLOCK,
    ))
    try:
        yield state
    finally:
        for fd in list(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def assert_closed(state, key):
    fd = state[key]
    assert state['calls'].count(fd) == 1
    with pytest.raises(OSError) as raised:
        os.fstat(fd)
    assert raised.value.errno == errno.EBADF


@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('child_fails', [False, True], ids=['child-close-ok', 'child-close-fails'])
def test_parent_retirement_failure_closes_unreturned_child(lock_state, error_type, child_fails):
    primary = error_type('parent retired')
    lock_state['parent_error'] = primary
    if child_fails:
        lock_state['child_error'] = OSError('child retired')
    with pytest.raises(error_type) as raised:
        with writer._lock(lock_state['directory']):
            pytest.fail('parent retirement failed before lock acquisition')
    assert raised.value is primary
    assert_closed(lock_state, 'parent')
    assert_closed(lock_state, 'child')


def test_retired_parent_is_not_retried_after_owned_foreign_replacement(lock_state, tmp_path):
    guard_path = tmp_path / 'owned-guard'
    guard_path.write_bytes(b'owned guard bytes')
    guard = os.open(guard_path, os.O_RDONLY)
    lock_state['guard'] = guard
    lock_state['live'].add(guard)
    lock_state['recycle_parent'] = True
    failure = OSError('parent retired')
    lock_state['parent_error'] = failure
    with pytest.raises(OSError) as raised:
        with writer._lock(lock_state['directory']):
            pytest.fail('parent retirement failed')
    assert raised.value is failure
    assert lock_state['calls'].count(lock_state['parent']) == 1
    assert os.fstat(lock_state['parent']).st_ino == os.fstat(guard).st_ino
    assert os.pread(lock_state['parent'], 64, 0) == b'owned guard bytes'
    assert_closed(lock_state, 'child')


@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt, SystemExit])
def test_native_child_open_refusal_survives_parent_cleanup_error(lock_state, tmp_path, error_type):
    target = tmp_path / 'owned-target'
    target.write_bytes(b'unchanged')
    (lock_state['directory'] / '.lock').symlink_to(target)
    lock_state['parent_error'] = error_type('parent retired')
    with pytest.raises(OSError) as raised:
        with writer._lock(lock_state['directory']):
            pytest.fail('native no-follow must refuse the symlink')
    assert raised.value is lock_state['open_error']
    assert 'child' not in lock_state
    assert target.read_bytes() == b'unchanged'
    assert_closed(lock_state, 'parent')


@pytest.mark.parametrize('error_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_body_failure_survives_consumed_child_close_error(lock_state, error_type):
    primary = error_type('body failed')
    lock_state['child_error'] = OSError('child retired')
    with pytest.raises(error_type) as raised:
        with writer._lock(lock_state['directory']):
            raise primary
    assert raised.value is primary
    assert_closed(lock_state, 'parent')
    assert_closed(lock_state, 'child')


def test_fresh_child_close_error_is_visible(lock_state):
    failure = OSError('child retired')
    lock_state['child_error'] = failure
    with pytest.raises(OSError) as raised:
        with writer._lock(lock_state['directory']):
            pass
    assert raised.value is failure
    assert_closed(lock_state, 'child')


def test_native_lock_excludes_contender_and_releases_after_body(lock_state):
    contender = os.open(lock_state['directory'] / '.lock', os.O_CREAT | os.O_RDWR, 0o600)
    lock_state['live'].add(contender)
    with writer._lock(lock_state['directory']):
        with pytest.raises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(contender, fcntl.LOCK_UN)
    assert_closed(lock_state, 'parent')
    assert_closed(lock_state, 'child')


def test_native_nonregular_lock_refusal_survives_child_close_error(lock_state):
    os.mkfifo(lock_state['directory'] / '.lock', 0o600)
    lock_state['child_error'] = OSError('child retired')
    with pytest.raises(ValueError, match='not a regular file'):
        with writer._lock(lock_state['directory']):
            pytest.fail('native FIFO must be refused')
    assert_closed(lock_state, 'child')
