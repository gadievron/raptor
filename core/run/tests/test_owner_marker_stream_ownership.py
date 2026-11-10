"""Owner-marker reads retain literal PID refusal and descriptor ownership."""

import errno
import io
import json
import os
from types import SimpleNamespace

import pytest

from core.run import tmp_ownership as ownership


@pytest.fixture
def marker(tmp_path, monkeypatch):
    path = tmp_path / '.owner.json'
    path.write_text(json.dumps({'pid': os.getpid()}))
    guard_path = tmp_path / 'owned-guard'
    guard_path.write_bytes(b'owned marker guard')
    guard = os.open(guard_path, os.O_RDONLY)
    state = {'path': path, 'guard': guard, 'live': {guard}, 'setup_error': None,
             'read_error': None, 'stream_close_error': None, 'raw_close_error': None,
             'replacement': None, 'close_calls': [], 'wrappers': 0}

    def open_marker(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state['fd'] = fd
        state['live'].add(fd)
        return fd

    def close(fd):
        state['close_calls'].append(fd)
        os.close(fd)
        state['live'].discard(fd)
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

    monkeypatch.setattr(ownership, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_marker, 'close': close, 'fdopen': fdopen},
    ))
    try:
        yield state
    finally:
        for fd in list(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def assert_retired(state):
    assert state['close_calls'].count(state['fd']) == 1
    with pytest.raises(OSError) as raised:
        os.fstat(state['fd'])
    assert raised.value.errno == errno.EBADF


def expect_primary(state, primary):
    if isinstance(primary, (OSError, ValueError)):
        assert ownership._owner_pid(state['path']) is None
    else:
        with pytest.raises(type(primary)) as raised:
            ownership._owner_pid(state['path'])
        assert raised.value is primary


@pytest.mark.parametrize('error_type', [OSError, ValueError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('raw_fails', [False, True], ids=['raw-close-ok', 'raw-close-cancel'])
def test_marker_setup_never_retries_consumed_descriptor(marker, error_type, raw_fails):
    primary = error_type('marker setup failed')
    marker['setup_error'] = primary
    if raw_fails:
        marker['raw_close_error'] = KeyboardInterrupt('raw close consumed')
    expect_primary(marker, primary)
    if marker['replacement'] is not None:
        assert os.pread(marker['replacement'], 64, 0) == b'owned marker guard'
    assert os.pread(marker['guard'], 64, 0) == b'owned marker guard'
    assert_retired(marker)


@pytest.mark.parametrize('error_type', [OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_marker_read_retains_primary_over_cleanup_failures(marker, error_type):
    primary = error_type('marker read failed')
    marker['read_error'] = primary
    marker['stream_close_error'] = OSError('stream close failed')
    marker['raw_close_error'] = KeyboardInterrupt('raw close consumed')
    expect_primary(marker, primary)
    assert_retired(marker)


@pytest.mark.parametrize('kind', ['fifo', 'oversized'])
def test_marker_pre_adoption_refusal_keeps_best_effort_close(marker, kind):
    marker['path'].unlink()
    if kind == 'fifo':
        os.mkfifo(marker['path'], 0o600)
    else:
        marker['path'].write_bytes(b' ' * (ownership._MARKER_MAX_BYTES + 1))
    marker['raw_close_error'] = OSError('raw close consumed')
    assert ownership._owner_pid(marker['path']) is None
    assert marker['wrappers'] == 0
    assert_retired(marker)


def test_native_valid_marker_returns_current_pid(marker):
    assert ownership._owner_pid(marker['path']) == os.getpid()
    assert_retired(marker)


@pytest.mark.parametrize('stage', ['stream', 'raw'])
def test_marker_fresh_close_error_refuses_pid(marker, stage):
    marker[stage + '_close_error'] = OSError('close consumed')
    assert ownership._owner_pid(marker['path']) is None
    assert_retired(marker)


@pytest.mark.parametrize('stage', ['stream', 'raw'])
def test_marker_fresh_close_cancellation_still_propagates(marker, stage):
    failure = KeyboardInterrupt('close consumed')
    marker[stage + '_close_error'] = failure
    with pytest.raises(KeyboardInterrupt) as raised:
        ownership._owner_pid(marker['path'])
    assert raised.value is failure
    assert_retired(marker)


@pytest.mark.parametrize('body', [b'not-json', b'[]'], ids=['malformed', 'non-object'])
def test_native_invalid_marker_stays_refused(marker, body):
    marker['path'].write_bytes(body)
    assert ownership._owner_pid(marker['path']) is None
    assert_retired(marker)
