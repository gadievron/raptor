"""A nested review cannot replace an active assigned unit with a display alias."""
from contextvars import copy_context
import json

import pytest

from core.audit.context import assemble_context
from core.audit.knowledge_calls import KnowledgeCallRefused
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients


@pytest.mark.slow
def test_nested_review_labels_cannot_restart_owned_unit_allowance(tmp_path, sdk_clients):
    source = tmp_path / 'unit.py'
    source.write_text('def f():\n    return 1\n')
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
    review = make_review_fn(bundle.client, schema=schema, escalate_clean=False)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float('inf'), window=0)
    config = OrchestratorConfig(target_path=tmp_path, out_dir=out, enable_session_context=False,
        immediate_verify=False, sweep_validate_findings=False, llm_budget_client=bundle.client)
    ctx = assemble_context(target_path=tmp_path, file_path='unit.py', function_name='f',
                           line_start=1, line_end=2)
    wrapped = runtime.wrap_review(review)
    outcomes = []
    def helper(gap):
        for index in range(7):
            current = dict(ctx)
            if index:
                current['function'] = f'f_alias_{index}'
            try:
                outcomes.append(wrapped(current, config))
            except KnowledgeCallRefused as refusal:
                return refusal
        return None
    try:
        refusal = runtime.wrap_unit(helper)({'file': 'unit.py', 'name': 'f', 'line_start': 1})
        assert len(bundle.state['requests']) <= 6, 'nested review replaced the assigned unit allowance'
        assert isinstance(refusal, KnowledgeCallRefused)
        assert refusal.reason == 'review_unit_identity_mismatch'
        assert len(outcomes) == len(bundle.state['requests']) == bundle.client._governed_calls == 1
        assert runtime._calls == {('unit.py', 'f', 1): 1}
        assert outcomes[0].cost_usd > 0
        assert not runtime._busy
    finally:
        runtime.close('test_complete')


@pytest.mark.slow
def test_finished_unit_context_cannot_start_a_fresh_sdk_review(tmp_path, sdk_clients):
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
    first = runtime.wrap_review(make_review_fn(bundle.client, schema=schema, escalate_clean=False))
    late = runtime.wrap_review(make_review_fn(bundle.client, schema=schema, escalate_clean=False,
                                              system_prompt='A distinct late review'))
    outcomes = []
    def helper(gap):
        outcomes.append(first(ctx, config))
        return copy_context()
    try:
        borrowed = runtime.wrap_unit(helper)({'file': 'unit.py', 'name': 'f', 'line_start': 1})
        with pytest.raises(KnowledgeCallRefused, match='unit_scope_closed'):
            borrowed.run(late, ctx, config)
        assert len(bundle.state['requests']) == bundle.client._governed_calls == 1
        assert runtime._calls == {('unit.py', 'f', 1): 1}
        assert outcomes[0].cost_usd > 0 and not runtime._busy
    finally:
        runtime.close('test_complete')
