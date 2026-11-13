"""Non-finite handle deadlines refuse before polling or signalling."""
import pytest

from core.sandbox.supervised import SupervisedHandle


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf')])
@pytest.mark.parametrize('method', ['wait', 'terminate'])
def test_nonfinite_deadline_refuses_before_handle_state(value, method):
    handle = _handle()
    events = []

    def forbidden():
        events.append('poll')
        pytest.fail('invalid deadline reached handle state')

    handle._poll_locked = forbidden
    with pytest.raises(ValueError, match='finite'):
        getattr(handle, method)(value)
    assert events == []
    assert handle.returncode is None


@pytest.mark.parametrize('value', [None, -1.0, 0.0, 0.5])
def test_wait_retains_completed_finite_and_unbounded_behavior(value):
    handle = _handle()
    handle.returncode = 0
    handle._poll_locked = lambda: 0
    assert handle.wait(value) == 0


@pytest.mark.parametrize('value', [-1.0, 0.0, 0.5])
def test_terminate_retains_completed_finite_behavior(value):
    handle = _handle()
    handle.returncode = 0
    handle._poll_locked = lambda: 0
    assert handle.terminate(value) == 0


def test_zero_wait_on_live_handle_still_times_out():
    handle = _handle()
    handle._poll_locked = lambda: None
    with pytest.raises(TimeoutError):
        handle.wait(0.0)
    assert handle.returncode is None


def _handle():
    # No process or descriptor acquired: only handle-owned lock/state.
    return SupervisedHandle(tier='pidns', pid=71, target_pid=73,
                            on_parent_death='survive', name='owned inert handle')
