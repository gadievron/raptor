"""Direct native handle release consumes ownership despite cleanup cancellation."""

import fcntl
import os
from types import SimpleNamespace

import pytest

from core.audit import run_lock


@pytest.fixture
def handle(tmp_path, monkeypatch):
    path = tmp_path / 'owned-lock'
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    owner = run_lock.RunLockHandle(fd, path)
    held = [owner]
    state = {'handle': owner, 'held': held, 'fd': fd, 'live': True,
             'close_error': None, 'unlock_error': None, 'closes': 0,
             'foreign': None, 'closed_foreign': False}

    def unlock(number, operation):
        fcntl.flock(number, operation)
        if state['unlock_error'] is not None:
            raise state['unlock_error']

    def close(number):
        if state['live']:
            assert number == fd
            os.close(number)
            state['live'] = False
            state['closes'] += 1
            foreign = os.open(tmp_path / 'owned-independent-file',
                              os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            assert foreign == number
            state['foreign'] = foreign
            info = os.fstat(foreign)
            state['identity'] = info.st_dev, info.st_ino
            if state['close_error'] is not None:
                raise state['close_error']
        else:
            assert number == state['foreign']
            info = os.fstat(number)
            assert (info.st_dev, info.st_ino) == state['identity']
            state['closed_foreign'] = True
            state['foreign'] = None
            os.close(number)

    monkeypatch.setattr(run_lock, '_HELD', held)
    monkeypatch.setattr(run_lock, 'os', SimpleNamespace(**{**vars(os), 'close': close}))
    monkeypatch.setattr(run_lock, 'fcntl', SimpleNamespace(
        **{**vars(fcntl), 'flock': unlock}))
    try:
        yield state
    finally:
        if state['live']:
            os.close(fd)
        if state['foreign'] is not None:
            os.close(state['foreign'])


@pytest.mark.parametrize('failure_type', [KeyboardInterrupt, SystemExit])
def test_close_cancellation_retires_handle_before_retry(handle, failure_type):
    failure = failure_type('consumed native close cancelled')
    handle['close_error'] = failure
    with pytest.raises(failure_type) as raised:
        handle['handle'].release()
    assert raised.value is failure
    handle['close_error'] = None
    handle['handle'].release()
    assert not handle['closed_foreign']
    assert not handle['handle'].held and not handle['held']
    assert handle['closes'] == 1


@pytest.mark.parametrize('primary_type', [KeyboardInterrupt, SystemExit, MemoryError])
@pytest.mark.parametrize('close_fails', [False, True])
def test_unlock_error_still_consumes_descriptor(handle, primary_type, close_fails):
    primary = primary_type('native unlock cancelled')
    handle['unlock_error'] = primary
    if close_fails:
        handle['close_error'] = SystemExit('secondary close cancelled')
    with pytest.raises(primary_type) as raised:
        handle['handle'].release()
    assert raised.value is primary
    assert handle['closes'] == 1 and not handle['live']
    assert not handle['handle'].held and not handle['held']


@pytest.mark.parametrize('has_fcntl', [False, True])
@pytest.mark.parametrize('close_fails', [False, True])
@pytest.mark.parametrize('unlock_fails', [False, True])
def test_io_errors_remain_best_effort_and_release_is_idempotent(
        handle, close_fails, unlock_fails, has_fcntl, monkeypatch):
    monkeypatch.setattr(run_lock, '_HAS_FCNTL', has_fcntl)
    if close_fails:
        handle['close_error'] = OSError('consumed native close failed')
    if unlock_fails:
        handle['unlock_error'] = OSError('native unlock failed')
    handle['handle'].release()
    handle['handle'].release()
    assert handle['closes'] == 1 and not handle['live']
    assert not handle['closed_foreign']
    assert not handle['handle'].held and not handle['held']
