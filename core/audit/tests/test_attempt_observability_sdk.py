"""Captured SDK attempts remain explicitly unknown behind opaque adapters."""
import json

import pytest

from core.audit.context import assemble_context
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients


@pytest.mark.slow
def test_opaque_client_attempts_are_not_exported_as_complete(tmp_path, sdk_clients):
    (tmp_path / 'unit.py').write_text('def f():\n    return 1\n')
    out = tmp_path / 'run'
    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)
    def transform(response):
        message = response['choices'][0]['message']
        payload = {'status': 'clean', 'body': 'Captured owned reviewer assessment'}
        if message.get('tool_calls'):
            message['tool_calls'][0]['function']['arguments'] = json.dumps(payload)
        else:
            message['content'] = json.dumps(payload)
        return response
    bundle.state['transform'] = transform
    schema = {'type': 'object', 'properties': {'status': {'type': 'string'}, 'body': {'type': 'string'}},
              'required': ['status', 'body']}
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float('inf'), window=0)
    config = OrchestratorConfig(target_path=tmp_path, out_dir=out, enable_session_context=False,
        immediate_verify=False, sweep_validate_findings=False, llm_budget_client=bundle.client)
    ctx = assemble_context(target_path=tmp_path, file_path='unit.py', function_name='f',
                           line_start=1, line_end=2)
    class OpaqueClient:
        _attempt_admission_protocol = None
        def __getattr__(self, name):
            return getattr(bundle.client, name)
        def generate_structured(self, *args, **kwargs):
            for _ in range(3):
                result = bundle.client.generate_structured(*args, **{**kwargs, 'cache': False})
            return result
    first = runtime.wrap_review(make_review_fn(OpaqueClient(), schema=schema, escalate_clean=False))
    try:
        outcome = first(ctx, config)
        assert outcome.cost_usd > 0
        assert len(bundle.state['requests']) == bundle.client._governed_calls == 3
        assert runtime._calls == {('unit.py', 'f', 1): 1}
        runtime._register(runtime._origin(ctx), ctx, {
            "language_reference_requests": [{"topic": "integer promotion"}]})
        runtime.write_artifacts(out)
        record = json.loads((out / 'knowledge-results.json').read_text())
        assert record['units'][0]['all_model_calls'] is None, record['units']
        assert record['units'][0]['owned_dispatch_attempts'] == 1
        assert not runtime.ready_continuations(admission=lambda: True)
    finally:
        runtime.close('test_complete')
