"""Shared key-file descriptor precedence without invoking key consumers."""

import errno
import os
import stat
from types import SimpleNamespace

import pytest

from core.security import mac_key


@pytest.fixture
def key_io(tmp_path, monkeypatch):
    path = tmp_path / 'owned-private' / 'inert.key'
    data = b'k' * 32
    state = {'path': path, 'data': data, 'read_error': None, 'write_error': None,
             'warn_error': None, 'close_error': None, 'live': set(), 'closes': 0, 'warnings': []}

    def open_file(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state['live'].add(fd)
        return fd

    def read(fd, size):
        result = os.read(fd, size)
        if state['read_error'] is not None:
            raise state['read_error']
        return result

    def write(fd, data):
        result = os.write(fd, data)
        if state['write_error'] is not None:
            raise state['write_error']
        return result

    def close(fd):
        os.close(fd)
        state['live'].remove(fd)
        state['closes'] += 1
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
        if state['close_error'] is not None:
            raise state['close_error']

    def warn(*args):
        state['warnings'].append(args)
        if state['warn_error'] is not None:
            raise state['warn_error']

    state['warn'] = warn
    monkeypatch.setattr(mac_key, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_file, 'read': read, 'write': write, 'close': close},
    ))
    monkeypatch.setattr(mac_key, 'secrets', SimpleNamespace(token_bytes=lambda size: data))
    try:
        yield state
    finally:
        for fd in tuple(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def existing(state, *, mode=0o600):
    state['path'].parent.mkdir(mode=0o700)
    state['path'].write_bytes(state['data'])
    state['path'].chmod(mode)


def read_key(state):
    return mac_key.read_existing_key(state['path'], key_len=32, warn=state['warn'])


def create_key(state):
    return mac_key.load_or_create_key(state['path'], key_len=32, warn=state['warn'])


@pytest.mark.parametrize('primary_type,cleanup_type', [
    pytest.param(OSError, OSError, id='ordinary'),
    pytest.param(OSError, KeyboardInterrupt, id='cleanup-interrupt'),
    pytest.param(OSError, SystemExit, id='cleanup-exit'),
    pytest.param(ValueError, KeyboardInterrupt, id='primary-value'),
    pytest.param(MemoryError, KeyboardInterrupt, id='primary-memory'),
    pytest.param(KeyboardInterrupt, OSError, id='primary-interrupt'),
    pytest.param(SystemExit, KeyboardInterrupt, id='primary-exit'),
])
def test_native_key_write_primary_survives_close(key_io, primary_type, cleanup_type):
    primary = primary_type('primary key write failed')
    key_io['write_error'] = primary
    key_io['close_error'] = cleanup_type('native close consumed')
    with pytest.raises(primary_type) as raised:
        create_key(key_io)
    assert raised.value is primary
    assert key_io['closes'] == 1 and not key_io['live']
    assert key_io['path'].read_bytes() == key_io['data']


@pytest.mark.parametrize('primary_type', [ValueError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt])
def test_native_read_callback_primary_survives_close(key_io, primary_type, cleanup_type):
    existing(key_io, mode=0o640)
    primary = primary_type('primary refusal callback failed')
    key_io['warn_error'] = primary
    key_io['close_error'] = cleanup_type('native close consumed')
    with pytest.raises(primary_type) as raised:
        read_key(key_io)
    assert raised.value is primary
    assert len(key_io['warnings']) == 1
    assert key_io['closes'] == 1 and not key_io['live']


@pytest.mark.parametrize('stage', ['read', 'create'])
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_key_close_error_remains_observable(key_io, stage, cleanup_type):
    if stage == 'read':
        existing(key_io)
    failure = cleanup_type('fresh native close consumed')
    key_io['close_error'] = failure
    with pytest.raises(cleanup_type) as raised:
        (read_key if stage == 'read' else create_key)(key_io)
    assert raised.value is failure
    assert key_io['closes'] == 1 and not key_io['live']


@pytest.mark.parametrize('cleanup_type', [None, OSError, KeyboardInterrupt])
def test_handled_read_oserror_keeps_fresh_close_policy(key_io, cleanup_type):
    existing(key_io)
    key_io['read_error'] = OSError('handled native read error')
    if cleanup_type is None:
        assert read_key(key_io) is None
    else:
        cleanup = cleanup_type('fresh native close consumed')
        key_io['close_error'] = cleanup
        with pytest.raises(cleanup_type) as raised:
            read_key(key_io)
        assert raised.value is cleanup
    assert key_io['closes'] == 1 and not key_io['live']


def test_native_private_key_create_and_read_unchanged(key_io):
    assert create_key(key_io) == key_io['data']
    assert stat.S_IMODE(key_io['path'].stat().st_mode) == 0o600
    assert stat.S_IMODE(key_io['path'].parent.stat().st_mode) == 0o700
    assert read_key(key_io) == key_io['data']
    assert key_io['closes'] == 2 and not key_io['live']
    assert not key_io['warnings']


def test_native_metadata_refusal_remains_sentinel(key_io):
    existing(key_io, mode=0o640)
    assert read_key(key_io) is mac_key.REFUSED
    assert len(key_io['warnings']) == 1
    assert key_io['closes'] == 1 and not key_io['live']
