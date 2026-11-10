"""Recall log descriptors stay owned when native stream setup fails."""

import errno
import io
import os
import subprocess
from types import SimpleNamespace

import pytest

from core.recall import runner
from core.recall.tests.test_runner import _manifest
from core.source import streams


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    output = tmp_path / 'owned-output'
    output.mkdir()
    state = {'root': tmp_path, 'output': output, 'log': tmp_path / 'pipeline.log',
             'roles': {}, 'opened': [], 'closed': [], 'live': set(), 'calls': 0,
             'fail_role': None, 'primary': None, 'close_error_role': None,
             'close_error': None, 'process_calls': 0, 'process_error': None, 'seen': {}}

    def finish(fd, role):
        state['live'].discard(fd)
        state['roles'].pop(fd, None)
        state['closed'].append(role)
        if role == state['close_error_role']:
            raise state['close_error']

    def close(fd):
        role = state['roles'].get(fd)
        os.close(fd)
        if role is not None:
            finish(fd, role)

    def fdopen(fd, mode='r', **kwargs):
        state['calls'] += 1
        role = state['calls']
        state['roles'][fd] = role
        state['opened'].append((role, fd))
        state['live'].add(fd)
        if role == state['fail_role']:
            raise state['primary']

        class Closing:
            def close(self):
                if self.closed:
                    return
                owns_fd = self.raw.closefd
                super().close()
                if owns_fd:
                    finish(fd, role)

        class Reader(Closing, io.BufferedReader):
            pass

        class Writer(Closing, io.BufferedWriter):
            pass

        raw = io.FileIO(fd, mode, closefd=kwargs.pop('closefd', True))
        stream = Reader(raw) if 'r' in mode else Writer(raw)
        if 'b' not in mode:
            return io.TextIOWrapper(stream, **kwargs)
        return stream

    def run(argv, **kwargs):
        state['process_calls'] += 1
        state['seen'] = kwargs
        kwargs['stdout'].write(f'noise\nOUTPUT_DIR={output}\n'.encode())
        kwargs['stderr'].write(b'owned stderr\n')
        if state['process_error'] is not None:
            raise state['process_error']
        return SimpleNamespace(returncode=0)

    private_os = SimpleNamespace(**{**vars(os), 'fdopen': fdopen, 'close': close})
    # The old caller and the shared owner resolve different module bindings.
    # Both bindings remain private to this worker; stdlib os stays unchanged.
    monkeypatch.setattr(runner, 'os', private_os, raising=False)
    monkeypatch.setattr(streams, 'os', private_os)
    monkeypatch.setattr(runner, 'subprocess', SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired))
    try:
        yield state
    finally:
        for fd in list(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def invoke(state):
    return runner.run_pipeline(_manifest(), state['root'] / 'unused-target', state['root'], state['log'])


def assert_all_closed(state):
    for role, fd in state['opened']:
        with pytest.raises(OSError) as raised:
            os.fstat(fd)
        assert raised.value.errno == errno.EBADF
        assert state['closed'].count(role) == 1
    assert not state['live']
    assert not state['log'].with_suffix('.log.stderr.tmp').exists()


@pytest.mark.parametrize('role', [1, 2, 3, 4, 5], ids=['stdout', 'stderr', 'sentinel', 'append', 'stderr-read'])
@pytest.mark.parametrize('error_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
def test_setup_failure_retires_unreturned_native_log_descriptor(pipeline, role, error_type):
    primary = error_type('native stream setup failed')
    pipeline['fail_role'], pipeline['primary'] = role, primary
    pipeline['close_error_role'] = role
    pipeline['close_error'] = OSError('raw close consumed')
    expected = runner.RunnerError if error_type is OSError and role >= 3 else error_type
    with pytest.raises(expected) as raised:
        invoke(pipeline)
    if expected is runner.RunnerError:
        assert raised.value.__cause__ is primary
        assert 'hardened reopen' in str(raised.value)
    else:
        assert raised.value is primary
    assert pipeline['process_calls'] == (0 if role <= 2 else 1)
    assert_all_closed(pipeline)


@pytest.mark.parametrize('role', [1, 2, 3, 4, 5], ids=['stdout', 'stderr', 'sentinel', 'append', 'stderr-read'])
def test_fresh_native_close_failure_stays_visible(pipeline, role):
    failure = OSError('raw close consumed')
    pipeline['close_error_role'], pipeline['close_error'] = role, failure
    expected = runner.RunnerError if role >= 3 else OSError
    with pytest.raises(expected) as raised:
        invoke(pipeline)
    assert (raised.value.__cause__ if role >= 3 else raised.value) is failure
    assert_all_closed(pipeline)


def test_timeout_error_survives_raw_cleanup_failure(pipeline):
    failure = subprocess.TimeoutExpired(['owned-local-consumer'], 1)
    pipeline['process_error'] = failure
    pipeline['close_error_role'] = 2
    pipeline['close_error'] = OSError('raw close consumed')
    with pytest.raises(runner.RunnerError, match='pipeline timed out') as raised:
        invoke(pipeline)
    assert raised.value.__cause__ is failure
    assert_all_closed(pipeline)


def test_native_stream_success_preserves_log_contract(pipeline):
    assert invoke(pipeline) == pipeline['output']
    assert pipeline['calls'] == 5
    assert pipeline['process_calls'] == 1
    assert pipeline['seen']['timeout'] == runner.DEFAULT_TIMEOUT_S
    assert pipeline['seen']['cwd'] == str(pipeline['root'])
    body = pipeline['log'].read_text()
    assert body == f"noise\nOUTPUT_DIR={pipeline['output']}\n\n--- stderr ---\nowned stderr\n"
    assert_all_closed(pipeline)
