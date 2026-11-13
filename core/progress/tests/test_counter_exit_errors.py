"""Counter diagnostics preserve active body errors on borrowed native output."""
import pytest

from core import progress
from core.progress.tests.test_bar_exit_errors import borrowed, output as output
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def counter(output, monkeypatch):
    patch_module_attribute(monkeypatch, progress, 'sys', 'stderr', output.stream)
    return output


@pytest.mark.parametrize('primary', [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
@pytest.mark.parametrize('phase', ['write', 'flush'])
def test_counter_body_error_survives_native_diagnostic_failure(counter, primary, cleanup, phase):
    error = primary('owned counter body failure')
    counter.error, counter.phase = cleanup('after actual diagnostic IO'), phase
    with pytest.raises(primary) as caught:
        with progress.HackerProgress(operation='owned-counter'):
            counter.armed = True
            raise error
    assert caught.value is error
    assert 'failed:' in counter.path.read_text()
    borrowed(counter)


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt])
@pytest.mark.parametrize('phase', ['write', 'flush'])
def test_counter_fresh_finish_failure_remains_visible(counter, cleanup, phase):
    counter.error, counter.phase = cleanup('fresh counter finish failure'), phase
    with pytest.raises(cleanup) as caught:
        with progress.HackerProgress(operation='owned-counter'):
            counter.armed = True
    assert caught.value is counter.error
    assert 'Complete' in counter.path.read_text()
    borrowed(counter)


def test_counter_healthy_finish_keeps_borrowed_output(counter):
    with progress.HackerProgress(operation='owned-counter', total=2) as bar:
        bar.current = 2
    assert 'Complete 2/2' in counter.path.read_text()
    borrowed(counter)


def test_counter_healthy_failure_diagnostic_retains_body_identity(counter):
    error = SystemExit('counter stopped')
    with pytest.raises(SystemExit) as caught:
        with progress.HackerProgress(operation='owned-counter'):
            raise error
    assert caught.value is error
    assert "SystemExit('counter stopped')" in counter.path.read_text()
    borrowed(counter)


def test_disabled_counter_does_not_write_on_body_failure(counter):
    error = KeyboardInterrupt('disabled counter stopped')
    counter.error, counter.armed = MemoryError('must not write'), True
    with pytest.raises(KeyboardInterrupt) as caught:
        with progress.HackerProgress(operation='owned-counter', disabled=True):
            raise error
    assert caught.value is error and not counter.writes
    borrowed(counter)


def test_counter_keeps_unrepresentable_error_fallback(counter):
    class Unrepresentable(RuntimeError):
        def __repr__(self):
            raise ValueError('repr unavailable')

    error = Unrepresentable('body failed')
    with pytest.raises(Unrepresentable) as caught:
        with progress.HackerProgress(operation='owned-counter'):
            raise error
    assert caught.value is error
    assert '<unrepresentable exception>' in counter.path.read_text()
    borrowed(counter)
