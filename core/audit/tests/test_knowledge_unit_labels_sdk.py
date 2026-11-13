"""A helper's mutable labels cannot replace its already-owned unit allowance."""
import pytest

from core.audit.knowledge_calls import KnowledgeCallRefused, observed_client
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import StudyQueue
from core.audit.record import load_verified_audit_log
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients


@pytest.mark.slow
def test_owned_unit_labels_cannot_restart_actual_sdk_allowance(tmp_path, sdk_clients):
    source = tmp_path / 'unit.py'
    source.write_text('def f():\n    return 1\n')
    out = tmp_path / 'run'
    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float('inf'), window=0)
    gap = {'file': 'unit.py', 'name': 'f', 'line_start': 1, 'line_end': 2}
    original_key = runtime._gap_key(gap)
    def helper(current):
        client = observed_client(bundle.client, purpose='critic')
        for index in range(7):
            current['name'] = f'f_alias_{index}'
            try:
                client.generate(f'Captured owned helper dispatch {index}', max_tokens=64)
            except KnowledgeCallRefused as refusal:
                return refusal
        return None
    try:
        refusal = runtime.wrap_unit(helper)(gap)
        assert len(bundle.state['requests']) <= 6, 'mutable labels restarted one owned unit allowance'
        assert isinstance(refusal, KnowledgeCallRefused)
        assert len(bundle.state['requests']) == bundle.client._governed_calls == 6
        assert runtime._calls == {original_key: 6}
        records = load_verified_audit_log(out)
        admitted = [row for row in records if row.get('stage') == 'admitted']
        reported = [row for row in records if row.get('stage') == 'reported']
        assert len(admitted) == len(reported) == 6
        assert {row['attempt']['attempt_id'] for row in admitted} == {row['attempt']['attempt_id'] for row in reported}
        assert len({row['attempt']['attempt_id'] for row in admitted}) == 6
        assert bundle.client.reported_spend_usd > 0
        assert not bundle.client.pending_usage_reservations
        assert not bundle.client._prepared_resource_reservations
    finally:
        runtime.close('test_complete')


@pytest.mark.slow
def test_owned_unit_labels_cannot_restart_sdk_transport_retry_allowance(tmp_path, monkeypatch, sdk_clients):
    import httpx
    import core.llm.client as client_module
    from core.testing.module_bindings import patch_module_attribute
    patch_module_attribute(monkeypatch, client_module, 'time', 'sleep', lambda _: None)
    source = tmp_path / 'unit.py'
    source.write_text('def f():\n    return 1\n')
    out = tmp_path / 'run'
    bundle = sdk_clients(cap=20.0, token_cap=1000000, max_calls=20, retries=8, run_dir=out)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float('inf'), window=0)
    gap = {'file': 'unit.py', 'name': 'f', 'line_start': 1, 'line_end': 2}
    def lost_response(request):
        gap['name'] = f"f_retry_label_{len(bundle.state['requests'])}"
        raise httpx.ReadError('captured unknown transport completion', request=request)
    bundle.state['handler'] = lost_response
    def helper(current):
        client = observed_client(bundle.client, purpose='critic')
        with pytest.raises(KnowledgeCallRefused):
            client.generate('One owned helper with transport retries', max_tokens=64)
    try:
        runtime.wrap_unit(helper)(gap)
        assert len(bundle.state['requests']) == bundle.client._governed_calls == 6
        assert runtime._calls == {('unit.py', 'f', 1): 6}
        assert not runtime._busy
        records = load_verified_audit_log(out)
        admitted = [row for row in records if row.get('stage') == 'admitted']
        assert len(admitted) == len({row['attempt']['attempt_id'] for row in admitted}) == 6
        # Lost transport replies remain unknown/reserved, rather than free.
        assert len(bundle.client.pending_usage_reservations) == 6
        assert all(row['reservation_usd'] > 0 and row['reservation_tokens'] > 0
                   for row in bundle.client.pending_usage_reservations)
        assert not bundle.client.is_budget_exhausted(estimated_cost=0)
    finally:
        runtime.close('test_complete')
