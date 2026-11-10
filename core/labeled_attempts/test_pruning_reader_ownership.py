"""Pruning readers own native descriptors without changing record admission."""

import errno
import io
import os
from types import SimpleNamespace

import pytest

from core.labeled_attempts import pruning


@pytest.fixture
def record(tmp_path, monkeypatch):
    path = tmp_path / 'record.json'
    path.write_bytes(b'{"owned":true}')
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    guard_path = tmp_path / 'owned-guard'
    guard_path.write_bytes(b'owned guard bytes')
    guard = os.open(guard_path, os.O_RDONLY)
    state = {'path': path, 'directory': directory, 'guard': guard, 'live': {directory, guard},
             'setup_error': None, 'read_error': None, 'stream_close_error': None,
             'raw_close_error': None, 'replacement': None, 'close_calls': [], 'wrappers': 0}

    def open_record(*args, **kwargs):
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

    monkeypatch.setattr(pruning, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_record, 'close': close, 'fdopen': fdopen},
    ))
    try:
        yield state
    finally:
        for fd in list(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def read_record(state):
    return pruning._read_record(state['directory'], state['path'].name)


def assert_retired(state):
    assert state['close_calls'].count(state['fd']) == 1
    with pytest.raises(OSError) as raised:
        os.fstat(state['fd'])
    assert raised.value.errno == errno.EBADF


@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('raw_fails', [False, True], ids=['raw-close-ok', 'raw-close-fails'])
def test_setup_failure_never_retries_consumed_native_descriptor(record, error_type, raw_fails):
    primary = error_type('reader setup failed')
    record['setup_error'] = primary
    if raw_fails:
        record['raw_close_error'] = OSError('raw close consumed')
    with pytest.raises(error_type) as raised:
        read_record(record)
    assert raised.value is primary
    if record['replacement'] is not None:
        assert os.pread(record['replacement'], 64, 0) == b'owned guard bytes'
    assert os.pread(record['guard'], 64, 0) == b'owned guard bytes'
    assert_retired(record)


@pytest.mark.parametrize('error_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_read_primary_survives_stream_and_raw_cleanup_errors(record, error_type):
    primary = error_type('read refused')
    record['read_error'] = primary
    record['stream_close_error'] = OSError('stream close failed')
    record['raw_close_error'] = KeyboardInterrupt('raw close consumed')
    with pytest.raises(error_type) as raised:
        read_record(record)
    assert raised.value is primary
    assert_retired(record)


@pytest.mark.parametrize('kind', ['fifo', 'oversized'])
def test_pre_adoption_refusal_keeps_best_effort_close_policy(record, kind):
    record['path'].unlink()
    if kind == 'fifo':
        os.mkfifo(record['path'], 0o600)
    else:
        with record['path'].open('wb') as stream:
            stream.truncate(pruning._MAX_RECORD_BYTES + 1)
    record['raw_close_error'] = OSError('raw close consumed')
    assert read_record(record) is None
    assert record['wrappers'] == 0
    assert_retired(record)


def test_native_success_returns_exact_bytes_and_version(record):
    expected = record['path'].read_bytes()
    version = pruning._file_version(record['path'].stat())
    assert read_record(record) == (expected, version)
    assert_retired(record)


def test_fresh_stream_close_failure_refuses_success(record):
    failure = OSError('stream close failed')
    record['stream_close_error'] = failure
    with pytest.raises(OSError) as raised:
        read_record(record)
    assert raised.value is failure
    assert_retired(record)


def test_post_adoption_raw_close_failure_refuses_success(record):
    failure = OSError('raw close consumed')
    record['raw_close_error'] = failure
    with pytest.raises(OSError) as raised:
        read_record(record)
    assert raised.value is failure
    assert_retired(record)
