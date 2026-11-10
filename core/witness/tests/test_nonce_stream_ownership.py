"""Nonce reads retain native descriptor ownership and refusal semantics."""

import errno
import io
import os
from types import SimpleNamespace

import pytest

from core.witness import provenance as nonce_module


@pytest.fixture
def nonce(tmp_path, monkeypatch):
    payload = b'a' * nonce_module._NONCE_HEX_LEN
    path = tmp_path / nonce_module._BINDING_FILE
    path.write_bytes(payload)
    guard_path = tmp_path / 'owned-guard'
    guard_path.write_bytes(b'owned nonce guard')
    guard = os.open(guard_path, os.O_RDONLY)
    state = {'root': tmp_path, 'path': path, 'payload': payload, 'guard': guard,
             'live': {guard}, 'setup_error': None, 'read_error': None,
             'stream_close_error': None, 'raw_close_error': None, 'replacement': None,
             'replacement_closed': False, 'retired': [], 'closes': [], 'wrappers': 0, 'reads': []}

    def open_nonce(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state['fd'] = fd
        state['live'].add(fd)
        return fd

    def close(fd):
        state['closes'].append(fd)
        if fd == state['replacement']:
            actual, owned = os.fstat(fd), os.fstat(guard)
            assert (actual.st_dev, actual.st_ino) == (owned.st_dev, owned.st_ino)
            state['replacement_closed'] = True
        os.close(fd)
        state['live'].discard(fd)
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
        state['retired'].append(fd)
        if state['raw_close_error'] is not None:
            raise state['raw_close_error']

    def fdopen(fd, mode, **kwargs):
        state['wrappers'] += 1
        if state['setup_error'] is not None:
            stream = os.fdopen(fd, mode, **kwargs)
            owns_fd = stream.raw.closefd
            stream.close()
            if owns_fd:
                state['live'].discard(fd)
                os.dup2(guard, fd)
                state['live'].add(fd)
                state['replacement'] = fd
            raise state['setup_error']

        class Reader(io.BufferedReader):
            def read(self, size=-1):
                state['reads'].append(size)
                if state['read_error'] is not None:
                    raise state['read_error']
                return super().read(size)

            def close(self):
                if self.closed:
                    return
                owns_fd = self.raw.closefd
                super().close()
                if owns_fd:
                    state['live'].discard(fd)
                if state['stream_close_error'] is not None:
                    raise state['stream_close_error']

        return Reader(io.FileIO(fd, mode, closefd=kwargs.get('closefd', True)))

    monkeypatch.setattr(nonce_module, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_nonce, 'close': close, 'fdopen': fdopen},
    ))
    try:
        yield state
    finally:
        for fd in list(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def read_nonce(state):
    return nonce_module._read_run_nonce(state['root'])


def assert_retired(state):
    assert state['closes'].count(state['fd']) == 1
    assert state['retired'].count(state['fd']) == 1


def expect_primary(state, primary):
    if isinstance(primary, OSError):
        assert read_nonce(state) is None
    else:
        with pytest.raises(type(primary)) as raised:
            read_nonce(state)
        assert raised.value is primary


@pytest.mark.parametrize('error_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
def test_nonce_setup_never_retries_consumed_descriptor(nonce, error_type):
    primary = error_type('nonce setup failed')
    nonce['setup_error'] = primary
    expect_primary(nonce, primary)
    assert not nonce['replacement_closed']
    assert_retired(nonce)


@pytest.mark.parametrize('error_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_nonce_read_primary_survives_independent_cleanup(nonce, error_type):
    primary = error_type('nonce read failed')
    nonce['read_error'] = primary
    nonce['stream_close_error'] = OSError('stream close failed')
    nonce['raw_close_error'] = KeyboardInterrupt('raw close consumed')
    expect_primary(nonce, primary)
    assert_retired(nonce)


@pytest.mark.parametrize('stage', ['stream', 'raw'])
def test_nonce_fresh_close_error_refuses_read(nonce, stage):
    nonce[stage + '_close_error'] = OSError('close consumed')
    assert read_nonce(nonce) is None
    assert_retired(nonce)


@pytest.mark.parametrize('stage', ['stream', 'raw'])
def test_nonce_fresh_cancellation_propagates(nonce, stage):
    failure = KeyboardInterrupt('close consumed')
    nonce[stage + '_close_error'] = failure
    expect_primary(nonce, failure)
    assert_retired(nonce)


@pytest.mark.parametrize('payload', [b'a' * 32, b'not-a-nonce', b'\xff', b'a' * 80])
def test_nonce_native_format_and_read_cap(nonce, payload):
    nonce['path'].write_bytes(payload)
    expected = 'a' * 32 if payload == b'a' * 32 else None
    assert read_nonce(nonce) == expected
    assert nonce['reads'] == [nonce_module._NONCE_HEX_LEN + 16]
    assert_retired(nonce)


def test_nonce_native_regular_symlink_remains_supported(nonce, tmp_path):
    target = tmp_path / 'owned-target'
    target.write_bytes(nonce['payload'])
    nonce['path'].unlink()
    nonce['path'].symlink_to(target)
    assert read_nonce(nonce) == 'a' * 32
    assert_retired(nonce)


def test_nonce_nonregular_refusal_keeps_best_effort_close(nonce):
    nonce['path'].unlink()
    os.mkfifo(nonce['path'], 0o600)
    nonce['raw_close_error'] = OSError('close consumed')
    assert read_nonce(nonce) is None
    assert nonce['wrappers'] == 0 and not nonce['reads']
    assert_retired(nonce)
