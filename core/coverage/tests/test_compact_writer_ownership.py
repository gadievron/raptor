"""Compaction rewrite streams keep descriptor and primary-error ownership."""

import errno
import io
import os
import tempfile
from types import SimpleNamespace

import pytest

from core.coverage import journal_compact as compact
from core.coverage.journal import JOURNAL_FILENAME
from core.coverage.tests.test_journal_compact import _reemission_run


@pytest.fixture
def rewrite(tmp_path, monkeypatch):
    _reemission_run(tmp_path, n_functions=1, n_segments=3)
    journal = tmp_path / JOURNAL_FILENAME
    original = journal.read_bytes()
    guard_path = tmp_path / 'owned-guard'
    guard_path.write_bytes(b'owned unrelated descriptor')
    guard = os.open(guard_path, os.O_RDONLY)
    state = {'root': tmp_path, 'journal': journal, 'original': original,
             'guard': guard, 'live': {guard}, 'close_calls': [], 'replacement': None,
             'setup_error': None, 'write_error': None, 'stream_close_error': None, 'raw_close_error': None}

    def mkstemp(*args, **kwargs):
        fd, name = tempfile.mkstemp(*args, **kwargs)
        state['fd'], state['temporary'] = fd, name
        state['live'].add(fd)
        return fd, name

    def close(fd):
        state['close_calls'].append(fd)
        os.close(fd)
        state['live'].discard(fd)
        if fd == state.get('fd') and state['raw_close_error'] is not None:
            raise state['raw_close_error']

    def fdopen(fd, mode, **kwargs):
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

        class Writer(io.BufferedWriter):
            def write(self, data):
                if state['write_error'] is not None:
                    raise state['write_error']
                return super().write(data)

            def close(self):
                if self.closed:
                    return
                owns_fd = self.raw.closefd
                super().close()
                if owns_fd:
                    state['live'].discard(fd)
                if state['stream_close_error'] is not None:
                    raise state['stream_close_error']

        return Writer(io.FileIO(fd, mode, closefd=kwargs.get('closefd', True)))

    monkeypatch.setattr(compact, 'tempfile', SimpleNamespace(mkstemp=mkstemp))
    monkeypatch.setattr(compact, 'os', SimpleNamespace(**{**vars(os), 'fdopen': fdopen, 'close': close}))
    try:
        yield state
    finally:
        for fd in list(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def assert_unpublished(state):
    assert state['journal'].read_bytes() == state['original']
    assert not list(state['root'].glob('*.pre-*'))
    assert not list(state['root'].glob('.~compact-*'))
    assert not os.path.exists(state['temporary'])


def assert_raw_retired_once(state):
    assert state['close_calls'].count(state['fd']) == 1
    with pytest.raises(OSError) as raised:
        os.fstat(state['fd'])
    assert raised.value.errno == errno.EBADF


@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('raw_fails', [False, True], ids=['raw-close-ok', 'raw-close-fails'])
def test_failed_wrapper_does_not_retry_consumed_descriptor(rewrite, error_type, raw_fails):
    primary = error_type('stream setup failed')
    rewrite['setup_error'] = primary
    if raw_fails:
        rewrite['raw_close_error'] = OSError('raw close consumed')
    with pytest.raises(error_type) as raised:
        compact.compact_journal(rewrite['root'])
    assert raised.value is primary
    assert os.pread(rewrite['guard'], 64, 0) == b'owned unrelated descriptor'
    if rewrite['replacement'] is not None:
        # Old cleanup must not close this separately owned alias after the
        # failed native wrapper already consumed its original descriptor.
        assert os.pread(rewrite['replacement'], 64, 0) == b'owned unrelated descriptor'
    assert_raw_retired_once(rewrite)
    assert_unpublished(rewrite)


@pytest.mark.parametrize('error_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_rewrite_error_survives_stream_and_raw_cleanup_failures(rewrite, error_type):
    primary = error_type('write refused')
    rewrite['write_error'] = primary
    rewrite['stream_close_error'] = OSError('stream close failed')
    rewrite['raw_close_error'] = OSError('raw close consumed')
    with pytest.raises(error_type) as raised:
        compact.compact_journal(rewrite['root'])
    assert raised.value is primary
    assert_raw_retired_once(rewrite)
    assert_unpublished(rewrite)


def test_fresh_stream_close_failure_prevents_publication(rewrite):
    failure = OSError('stream close failed')
    rewrite['stream_close_error'] = failure
    with pytest.raises(OSError) as raised:
        compact.compact_journal(rewrite['root'])
    assert raised.value is failure
    assert_raw_retired_once(rewrite)
    assert_unpublished(rewrite)


def test_fresh_raw_close_failure_prevents_publication(rewrite):
    failure = OSError('raw close consumed')
    rewrite['raw_close_error'] = failure
    with pytest.raises(OSError) as raised:
        compact.compact_journal(rewrite['root'])
    assert raised.value is failure
    assert_raw_retired_once(rewrite)
    assert_unpublished(rewrite)
