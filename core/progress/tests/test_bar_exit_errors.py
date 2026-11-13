"""Progress diagnostics cannot replace an active context-body exception."""
import io
import os
from types import SimpleNamespace

import pytest

from core import progress


@pytest.fixture
def output(tmp_path):
    path = tmp_path / 'owned-progress.txt'
    state = SimpleNamespace(armed=False, phase='write', error=None, writes=[], flushes=0)

    class Writer(io.TextIOWrapper):
        def write(self, text):
            count = super().write(text)
            super().flush()
            state.writes.append(text)
            if state.armed and state.phase == 'write':
                raise state.error
            return count

        def flush(self):
            super().flush()
            state.flushes += 1
            if state.armed and state.phase == 'flush':
                raise state.error

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(progress._stage_local, 'name', None, raising=False)
        with path.open('wb') as raw:
            stream = Writer(raw, encoding='utf-8')
            state.stream, state.path = stream, path
            state.fd = stream.fileno()
            state.identity = os.fstat(state.fd)
            try:
                yield state
            finally:
                state.armed = False
                stream.close()


def borrowed(output):
    assert not output.stream.closed
    info = os.fstat(output.fd)
    assert (info.st_dev, info.st_ino) == (output.identity.st_dev, output.identity.st_ino)
    assert output.path.read_text() == ''.join(output.writes)


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
@pytest.mark.parametrize('phase', ['write', 'flush'])
def test_body_error_survives_native_diagnostic_failure(output, primary, cleanup, phase):
    error = primary('owned progress body failure')
    output.error, output.phase = cleanup('after actual diagnostic IO'), phase
    with pytest.raises(primary) as caught:
        with progress.HackerProgressBar(stream=output.stream) as bar:
            bar.stage('owned-stage')
            output.armed = True
            raise error
    assert caught.value is error
    assert 'interrupted' in output.path.read_text()
    borrowed(output)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt])
@pytest.mark.parametrize('phase', ['write', 'flush'])
def test_fresh_native_diagnostic_failure_remains_visible(output, cleanup, phase):
    output.error, output.phase = cleanup('fresh diagnostic failure'), phase
    with pytest.raises(cleanup) as caught:
        with progress.HackerProgressBar(stream=output.stream) as bar:
            bar.stage('owned-stage')
            output.armed = True
    assert caught.value is output.error
    assert 'owned-stage' in output.path.read_text()
    borrowed(output)


def test_healthy_finalization_keeps_borrowed_stream(output):
    with progress.HackerProgressBar(stream=output.stream) as bar:
        bar.stage('owned-stage')
    assert bar._stage is None
    assert 'owned-stage' in output.path.read_text()
    borrowed(output)


def test_healthy_interruption_diagnostic_keeps_body_identity(output):
    error = SystemExit('body stopped')
    with pytest.raises(SystemExit) as caught:
        with progress.HackerProgressBar(stream=output.stream) as bar:
            bar.stage('owned-stage')
            raise error
    assert caught.value is error and bar._stage is None
    assert 'interrupted' in output.path.read_text()
    borrowed(output)


def test_silent_mode_does_not_write_on_interruption(output):
    error = KeyboardInterrupt('silent body stopped')
    output.error, output.armed = MemoryError('must not write'), True
    with pytest.raises(KeyboardInterrupt) as caught:
        with progress.HackerProgressBar(stream=output.stream, disabled=True) as bar:
            bar.stage('owned-stage')
            raise error
    assert caught.value is error and not output.writes
    borrowed(output)
