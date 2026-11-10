"""Owned teardown cannot depend on successful diagnostic annotation."""

import os

import pytest

from core.sandbox import _capture, context
from core.sandbox.tests import test_teardown_first_lifecycle as lifecycle

owned = lifecycle.owned
monkeypatch = lifecycle.monkeypatch
pytestmark = [pytest.mark.slow,
              pytest.mark.skipif(os.name != 'posix', reason='owned POSIX process/pipe lifecycle')]


@pytest.mark.parametrize('primary_type', [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize('note_type', [MemoryError, KeyboardInterrupt])
def test_input_cleanup_note_failure_still_retires_child(owned, monkeypatch, primary_type, note_type):
    primary = primary_type('owned communication failure')

    def refuse_note(message):
        raise note_type('owned annotation refusal')

    monkeypatch.setattr(primary, 'add_note', refuse_note)

    class FailedInputCleanup(_capture.BoundedCommunicator):
        first_communication = True
        first_stop = True

        def communicate(self, *args, **kwargs):
            if self.first_communication:
                self.first_communication = False
                raise primary
            return super().communicate(*args, **kwargs)

        def stop_input(self):
            super().stop_input()
            if self.first_stop:
                self.first_stop = False
                raise OSError('owned after-close input refusal')

    monkeypatch.setattr(context, 'BoundedCommunicator', FailedInputCleanup)
    raised = None
    try:
        owned.invoke(max_capture_bytes=97, input=b'owned')
    except BaseException as error:
        raised = error
    process = owned.processes[0][0]
    assert owned.holder == [None], 'diagnostic failure skipped death-channel retirement'
    assert process.returncode == 0, 'owned child was not reaped through its normal death channel'
    assert raised is primary


@pytest.mark.parametrize('diagnostic_error', [MemoryError, KeyboardInterrupt],
                         ids=['allocation', 'interrupt'])
def test_warning_failure_cannot_skip_forced_kill(owned, monkeypatch, diagnostic_error):
    import subprocess

    owned.mode[0] = 'park'
    primary = subprocess.TimeoutExpired('owned request', 1, output=b'prefix')
    lifecycle.fault_once(owned, monkeypatch, primary)
    logger = context.logger

    class LoggerView:
        def __getattr__(self, name):
            return getattr(logger, name)

        def warning(self, *args, **kwargs):
            raise diagnostic_error('owned diagnostic refusal')

    monkeypatch.setattr(context, 'logger', LoggerView())
    raised = None
    try:
        owned.invoke()
    except BaseException as error:
        raised = error
    assert owned.processes[0][0].returncode == -9, 'diagnostic failure skipped owned process kill/reap'
    assert owned.holder == [None]
    assert raised is primary


@pytest.mark.parametrize('note_type', [MemoryError, KeyboardInterrupt])
def test_stream_cleanup_note_preserves_primary_and_closes_siblings(note_type):
    from contextlib import ExitStack
    import tempfile
    from types import SimpleNamespace

    primary = RuntimeError('owned operation failure')

    def refuse_note(message):
        raise note_type('owned stream annotation refusal')

    primary.add_note = refuse_note
    with ExitStack() as owners:
        streams = [owners.enter_context(tempfile.TemporaryFile()) for _ in range(3)]

        class PipeView:
            def __getattr__(self, name):
                return getattr(streams[0], name)

            def close(self):
                streams[0].close()
                raise OSError('owned consumed close acknowledgement')

        proc = SimpleNamespace(stdin=PipeView(), stdout=streams[1], stderr=streams[2])
        raised = None
        try:
            raise primary
        except BaseException:
            try:
                context._close_teardown_streams(proc, failure=primary)
            except BaseException as error:
                raised = error
            else:
                raised = primary
        assert all(stream.closed for stream in streams)
        assert raised is primary


@pytest.mark.parametrize('note_type', [MemoryError, KeyboardInterrupt])
def test_final_retirement_note_preserves_primary(owned, monkeypatch, note_type):
    primary = RuntimeError('owned communication failure')

    def refuse_note(message):
        raise note_type('owned final annotation refusal')

    monkeypatch.setattr(primary, 'add_note', refuse_note)

    def configure(proc):
        actual = proc.communicate
        calls = 0

        def communicate(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise primary
            if calls == 2:
                raise OSError('owned secondary drain refusal')
            return actual(*args, **kwargs)

        monkeypatch.setattr(proc, 'communicate', communicate)

    owned.configure[0] = configure
    raised = None
    try:
        owned.invoke()
    except BaseException as error:
        raised = error
    assert owned.holder == [None]
    assert owned.processes[0][0].returncode == 0
    assert raised is primary
