"""Opaque client adapters cannot certify complete per-unit attempt counts."""
import pytest

from core.audit.knowledge_calls import observed_client, owned_call_scope
from core.audit.tests.test_knowledge_runtime_coordinator import _runtime


@pytest.mark.parametrize('protocol', [None, True, '1', 1.0, 1], ids=['absent', 'bool', 'text', 'float', 'supported'])
def test_attempt_observability_controls_follow_on_unit_work(tmp_path, protocol):
    runtime, ctx = _runtime(tmp_path)
    callbacks = []
    class Client:
        _attempt_admission_protocol = protocol
        def generate(self, **kwargs):
            callback = kwargs.pop('accounting_attempt_admission', None)
            for _ in range(3):
                if callback is not None:
                    assert callback() is True
                callbacks.append('captured attempt')
            return 'captured response'
    key = (ctx['file'], ctx['function'], ctx['line_start'])
    try:
        result = runtime.wrap_unit(lambda gap: observed_client(Client()).generate())(
            {'file': key[0], 'name': key[1], 'line_start': key[2]})
        assert result == 'captured response' and len(callbacks) == 3
        known = type(protocol) is int and protocol == 1
        assert runtime._calls[key] == (3 if known else 1)
        assert (key in runtime._unknown_calls) is not known
        continuations = runtime.ready_continuations(admission=lambda: True)
        assert bool(continuations) is known
        for reservation in continuations:
            runtime.fail(reservation, 'test_complete')
    finally:
        runtime.close('test_complete')


def test_notification_is_bound_to_original_unit_after_gap_mutation(tmp_path):
    runtime, ctx = _runtime(tmp_path)
    gap = {'file': ctx['file'], 'name': ctx['function'], 'line_start': 1}
    class Client:
        def generate(self):
            return 'captured'
    def helper(current):
        current['name'] = 'later display alias'
        return observed_client(Client()).generate()
    try:
        assert runtime.wrap_unit(helper)(gap) == 'captured'
        assert runtime._unknown_calls == {('unit.c', 'f', 1)}
        assert runtime._calls == {('unit.c', 'f', 1): 1}
    finally:
        runtime.close('test_complete')


def test_scope_notification_is_optional_and_restored_after_nested_scope():
    unknown = []
    class Client:
        def generate(self):
            return 'captured'
    with owned_call_scope(lambda *args: True, on_unobserved_attempts=lambda: unknown.append('outer')):
        outer = observed_client(Client())
        with owned_call_scope(lambda *args: True):
            assert observed_client(Client()).generate() == 'captured'
        assert outer.generate() == 'captured'
    assert unknown == ['outer']
    with pytest.raises(TypeError, match='notification must be callable'):
        with owned_call_scope(lambda *args: True, on_unobserved_attempts=True):
            pytest.fail('invalid notifier entered scope')
