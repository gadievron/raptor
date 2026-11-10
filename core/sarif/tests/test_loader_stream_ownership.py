"""SARIF input streams retain descriptor ownership and refusal semantics."""

import errno
import hashlib
import io
import json
import os
from types import SimpleNamespace

import pytest

from core.sarif import parser


@pytest.fixture
def sarif(tmp_path, monkeypatch):
    path = tmp_path / 'owned.sarif'
    path.write_text(json.dumps({'version': '2.1.0', 'runs': []}))
    guard_path = tmp_path / 'owned-guard'
    guard_path.write_bytes(b'owned SARIF guard')
    guard = os.open(guard_path, os.O_RDONLY)
    state = {'path': path, 'guard': guard, 'live': {guard}, 'setup_error': None,
             'read_error': None, 'stream_close_error': None, 'raw_close_error': None,
             'replacement': None, 'replacement_closed': False, 'retired': [],
             'close_calls': [], 'wrappers': 0, 'metadata': {'retained': True}}

    def open_sarif(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state['fd'] = fd
        state['live'].add(fd)
        return fd

    def close(fd):
        state['close_calls'].append(fd)
        if fd == state['replacement']:
            before = os.fstat(fd)
            guard_info = os.fstat(guard)
            assert (before.st_dev, before.st_ino) == (guard_info.st_dev, guard_info.st_ino)
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

    monkeypatch.setattr(parser, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_sarif, 'close': close, 'fdopen': fdopen},
    ))
    try:
        yield state
    finally:
        for fd in list(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def load(state):
    return parser.load_sarif(state['path'], metadata=state['metadata'])


def assert_retired(state):
    assert state['close_calls'].count(state['fd']) == 1
    assert state['retired'].count(state['fd']) == 1


def expect_primary(state, primary):
    if isinstance(primary, OSError):
        assert load(state) is None
    else:
        with pytest.raises(type(primary)) as raised:
            load(state)
        assert raised.value is primary
    assert state['metadata'] == {'retained': True}


@pytest.mark.parametrize('error_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('raw_fails', [False, True], ids=['raw-close-ok', 'raw-close-cancel'])
def test_setup_failure_does_not_retry_consumed_native_descriptor(sarif, error_type, raw_fails):
    primary = error_type('SARIF setup failed')
    sarif['setup_error'] = primary
    if raw_fails:
        sarif['raw_close_error'] = KeyboardInterrupt('raw close consumed')
    expect_primary(sarif, primary)
    assert not sarif['replacement_closed']
    assert os.pread(sarif['guard'], 64, 0) == b'owned SARIF guard'
    assert_retired(sarif)


@pytest.mark.parametrize('error_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_read_primary_survives_stream_and_raw_cleanup_failures(sarif, error_type, caplog):
    primary = error_type('SARIF read failed')
    sarif['read_error'] = primary
    sarif['stream_close_error'] = OSError('stream close failed')
    sarif['raw_close_error'] = KeyboardInterrupt('raw close consumed')
    expect_primary(sarif, primary)
    if error_type is OSError:
        assert any("SARIF read failed" in item.getMessage() for item in caplog.records)
    assert_retired(sarif)


@pytest.mark.parametrize('kind', ['fifo', 'oversized'])
def test_pre_adoption_refusal_retains_best_effort_cleanup(sarif, kind):
    sarif['path'].unlink()
    if kind == 'fifo':
        os.mkfifo(sarif['path'], 0o600)
    else:
        with sarif['path'].open('wb') as stream:
            stream.truncate(parser.SARIF_MAX_BYTES + 1)
    sarif['raw_close_error'] = OSError('raw close consumed')
    assert load(sarif) is None
    assert sarif['wrappers'] == 0
    assert sarif['metadata'] == {'retained': True}
    assert_retired(sarif)


def test_native_success_retains_exact_document_and_metadata(sarif):
    raw = sarif['path'].read_bytes()
    assert load(sarif) == {'version': '2.1.0', 'runs': []}
    assert sarif['metadata'] == {'retained': True, 'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)}
    assert_retired(sarif)


@pytest.mark.parametrize('stage', ['stream', 'raw'])
def test_fresh_close_error_refuses_document_and_metadata(sarif, stage):
    sarif[stage + '_close_error'] = OSError('close consumed')
    assert load(sarif) is None
    assert sarif['metadata'] == {'retained': True}
    assert_retired(sarif)


@pytest.mark.parametrize('stage', ['stream', 'raw'])
def test_fresh_close_cancellation_still_propagates(sarif, stage):
    failure = KeyboardInterrupt('close consumed')
    sarif[stage + '_close_error'] = failure
    expect_primary(sarif, failure)
    assert_retired(sarif)


@pytest.mark.parametrize('body', [b'broken-json', b'[]'], ids=['malformed', 'non-object'])
def test_invalid_document_stays_refused(sarif, body):
    sarif['path'].write_bytes(body)
    assert load(sarif) is None
    assert sarif['metadata'] == {'retained': True}
    assert_retired(sarif)
