"""Invalid run deadlines refuse before any backend can execute work."""
import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.test_context_decision_pins import _Driver, _SpawnRecorder
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='inert Linux dispatcher preparation')


@pytest.fixture
def prepared(monkeypatch, tmp_path):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    recorder = _SpawnRecorder()
    _Driver(monkeypatch, recorder)

    def forbid(*args, **kwargs):
        pytest.fail('timeout admission must not launch a process')

    monkeypatch.setattr(context, '_run_teardown_first_timeout', forbid)
    patch_module_attribute(monkeypatch, context, 'subprocess', 'Popen', forbid)
    return recorder


@pytest.mark.parametrize('timeout', [float('nan'), float('inf'), float('-inf')],
                         ids=['nan', 'inf', 'negative-inf'])
def test_nonfinite_timeout_refuses_before_dispatch(prepared, tmp_path, timeout):
    with context.sandbox(profile='full', target=str(tmp_path)) as run:
        with pytest.raises(ValueError, match='timeout.*finite'):
            run(['/bin/true'], timeout=timeout)
    assert prepared.calls == []


@pytest.mark.parametrize('timeout', [None, -1, 0, 0.25])
def test_finite_or_unbounded_timeout_reaches_dispatch(prepared, tmp_path, timeout):
    with context.sandbox(profile='full', target=str(tmp_path)) as run:
        result = run(['/bin/true'], timeout=timeout)
    assert result.returncode == 0
    assert len(prepared.calls) == 1
    assert prepared.calls[0]['timeout'] == timeout
