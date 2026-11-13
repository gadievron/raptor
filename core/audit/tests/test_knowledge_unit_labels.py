"""Owned admissions retain the scheduled unit while helpers annotate gaps."""
import pytest

from core.audit.knowledge_calls import KnowledgeCallRefused, observed_client
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import StudyQueue


class CapturedClient:
    def __init__(self):
        self.calls = []

    def generate(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return 'captured'

    def generate_structured(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {'captured': True}


@pytest.mark.parametrize('field', ['name', 'file', 'line_start'])
@pytest.mark.parametrize('method', ['generate', 'generate_structured'])
def test_mutable_unit_labels_cannot_restart_configured_allowance(tmp_path, field, method):
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float('inf'),
                                    window=0, max_model_calls=2)
    gap = {'file': 'unit.py', 'name': 'f', 'line_start': 1}
    client = CapturedClient()
    def helper(current):
        view = observed_client(client, purpose='critic')
        for index in range(3):
            current[field] = index + 10 if field == 'line_start' else f'alias_{index}'
            try:
                getattr(view, method)(f'captured helper {index}')
            except KnowledgeCallRefused as refusal:
                return refusal
        return None
    try:
        refusal = runtime.wrap_unit(helper)(gap)
        assert isinstance(refusal, KnowledgeCallRefused)
        assert len(client.calls) == 2
        assert runtime._calls == {('unit.py', 'f', 1): 2}
        assert not runtime._busy
    finally:
        runtime.close('test_complete')


def test_nested_units_keep_separate_original_allowances(tmp_path):
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float('inf'),
                                    window=0, max_model_calls=2)
    outer_gap = {'file': 'unit.py', 'name': 'f', 'line_start': 1}
    inner_gap = {'file': 'unit.py', 'name': 'g', 'line_start': 4}
    client = CapturedClient()
    def inner(current):
        view = observed_client(client, purpose='routing')
        for index in range(2):
            current['name'] = f'g_alias_{index}'
            view.generate(f'inner {index}')
        with pytest.raises(KnowledgeCallRefused):
            view.generate('inner beyond cap')
    def outer(current):
        view = observed_client(client, purpose='critic')
        current['name'] = 'f_alias'
        view.generate('outer first')
        runtime.wrap_unit(inner)(inner_gap)
        view.generate('outer second')
        with pytest.raises(KnowledgeCallRefused):
            view.generate('outer beyond cap')
    try:
        runtime.wrap_unit(outer)(outer_gap)
        assert len(client.calls) == 4
        assert runtime._calls == {('unit.py', 'f', 1): 2, ('unit.py', 'g', 4): 2}
        assert not runtime._busy
    finally:
        runtime.close('test_complete')
