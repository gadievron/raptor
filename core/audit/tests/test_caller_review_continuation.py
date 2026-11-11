"""Caller-code requests share bounded review ownership, not study semantics."""
import json

import pytest

from core.audit import capabilities, orchestrator as orch
from core.audit.context import format_context_for_prompt
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.wallclock import wall_deadline


@pytest.fixture(autouse=True)
def owned_shutdown():
    with isolated_audit_shutdown(orch):
        yield


def case(tmp_path, **policy):
    (tmp_path / 'unit.py').write_text('def f(n):\n    return n + 1\n')
    (tmp_path / 'caller.py').write_text('def caller(n):\n    return f(n)\n')
    inventory = {'files': [{'path': 'caller.py', 'items': [
        {'name': 'caller', 'kind': 'function', 'line_start': 1, 'line_end': 2},
    ]}]}
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float('inf'),
                                    window=0, caller_inventory=inventory, **policy)
    ctx = {'file': 'unit.py', 'function': 'f', 'line_start': 1,
           'source': 'def f(n):\n    return n + 1', 'language': 'python'}
    request = {'caller_context_requests': [{'file': 'caller.py', 'function': 'caller',
                'line_start': 1, 'reason': 'Does this caller validate n?'}]}
    return runtime, ctx, request


def test_source_request_reserves_normal_review_without_study_or_authority(tmp_path):
    runtime, ctx, request = case(tmp_path)
    runtime._register_caller_requests(runtime._origin(ctx), request)
    assert runtime.requests() == () and len(runtime.caller_requests()) == 1
    assert runtime.study_queue.dequeue_batch(timeout=0) == []
    reservation, = runtime.ready_continuations(admission=lambda: True)
    assert reservation.packet.references == () and reservation.packet.explanations == ()
    assert len(reservation.packet.caller_contexts) == 1
    assert runtime.enrich_context(ctx, reservation)
    prompt = format_context_for_prompt(ctx)
    assert 'return f(n)' in prompt and 'Does this caller validate n?' in prompt
    assert ctx['caller_context_delivery'][0]['delivered'] is True
    assert runtime.complete(reservation, ctx)
    assert not runtime.ready_continuations(admission=lambda: True)


@pytest.mark.parametrize('endpoint', ['unit.py', 'caller.py'])
def test_changed_endpoint_cannot_publish_context_review(tmp_path, endpoint):
    runtime, ctx, request = case(tmp_path)
    runtime._register_caller_requests(runtime._origin(ctx), request)
    reservation, = runtime.ready_continuations(admission=lambda: True)
    assert runtime.enrich_context(ctx, reservation)
    path = tmp_path / endpoint
    path.write_text(path.read_text() + '# changed after prompt preparation\n')
    assert not runtime.can_publish(reservation)
    assert runtime.fail(reservation, 'source_changed')
    assert not runtime.ready_continuations(admission=lambda: True)


def test_repeated_code_or_question_cannot_renew_round_allowance(tmp_path):
    runtime, ctx, request = case(tmp_path, max_continuations=2)
    runtime._register_caller_requests(runtime._origin(ctx), request)
    first, = runtime.ready_continuations(admission=lambda: True)
    assert runtime.complete(first, ctx)
    request['caller_context_requests'][0]['reason'] = 'A differently worded question about the same code'
    runtime._register_caller_requests(runtime._origin(ctx), request)
    assert not runtime.ready_continuations(admission=lambda: True)
    (tmp_path / 'caller.py').write_text('def caller(n):\n    return f(n + 2)\n')
    runtime._register_caller_requests(runtime._origin(ctx), request)
    second, = runtime.ready_continuations(admission=lambda: True)
    assert runtime.fail(second, 'scripted_failure')
    (tmp_path / 'caller.py').write_text('def caller(n):\n    return f(n + 3)\n')
    runtime._register_caller_requests(runtime._origin(ctx), request)
    assert not runtime.ready_continuations(admission=lambda: True)
    assert any(e.get('answer', {}).get('reason') == 'continuation_limit' for e in runtime.events())


def test_resolver_error_does_not_create_a_paid_call_or_study_job(tmp_path, monkeypatch):
    runtime, ctx, request = case(tmp_path)
    def fail(*args, **kwargs):
        raise RuntimeError('injected local resolver failure')
    monkeypatch.setattr('core.audit.knowledge_runtime.resolve_caller_context', fail)
    runtime._register_caller_requests(runtime._origin(ctx), request)
    assert not runtime.ready_continuations(admission=lambda: True)
    assert runtime.study_queue.dequeue_batch(timeout=0) == []
    assert any(e.get('answer', {}).get('reason') == 'caller_context_resolution_error' for e in runtime.events())


@pytest.mark.parametrize('drift', [False, True])
@pytest.mark.parametrize('second_status', ['clean', 'suspicious'])
def test_normal_audit_reviews_related_code_and_retains_original_assessment(tmp_path, monkeypatch, drift, second_status):
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'unit.py').write_text('def f(n):\n    return n + 1\n')
    (target / 'caller.py').write_text('def caller(n):\n    return f(n)\n')
    out = tmp_path / 'out'
    out.mkdir()
    checklist = {'files': [{'path': 'unit.py', 'items': [
        {'name': 'f', 'line_start': 1, 'line_end': 2},
    ]}]}
    (out / 'checklist.json').write_text(json.dumps(checklist))
    inventory = {'files': checklist['files'] + [{'path': 'caller.py', 'items': [
        {'name': 'caller', 'kind': 'function', 'line_start': 1, 'line_end': 2},
    ]}]}
    monkeypatch.setattr(orch, '_run_mechanical_detectors', lambda *args, **kwargs: ({}, set()))
    monkeypatch.setattr(orch, '_proactive_validate', lambda outcome, *args, **kwargs: outcome)
    monkeypatch.setattr(capabilities, 'probe_capabilities', lambda *args, **kwargs: capabilities.AuditCapabilities())
    calls = []

    class Client:
        _call_cost_history = None
        def is_budget_exhausted(self):
            return False
        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs['task_type'] == 'audit', 'caller context must not buy a study call'
            calls.append(prompt)
            if len(calls) == 1:
                assert 'caller_context_requests' in schema['properties']
                payload = {'status': 'suspicious', 'body': 'Caller premise is not established.',
                           'hypothesis': 'argument can reach f without validation',
                           'caller_context_requests': [{'file': 'caller.py', 'function': 'caller',
                              'line_start': 1, 'reason': 'Inspect whether this caller validates n.'}]}
            else:
                assert len(calls) == 2 and 'Requested caller-context code' in prompt
                assert 'return f(n)' in prompt
                if drift:
                    (target / 'caller.py').write_text('def caller(n):\n    return f(n + 9)\n')
                payload = {'status': second_status, 'body': 'Scripted reassessment, not a scoped refutation.',
                           'caller_context_requests': []}
            return StructuredResponse(result=payload, raw='', cost=0.2, model='scripted')

    client = Client()
    monkeypatch.setattr(orch, '_run_llm_client', lambda cfg: client)
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, inventory=inventory,
        max_workers=1, resume=False, prefilter=False, validate=False, immediate_verify=False,
        sweep_validate_findings=False, max_refinements=0, deepen_suspicious=False,
        open_discovery=False, sage_recall=False, iris=False,
        joern_overrides={'enabled': False}, llm_budget_client=client)
    with wall_deadline(30, code_bound_s=float('inf'), what='caller-context continuation'):
        result = orch.run_orchestrator(config, make_review_fn(client, escalate_clean=False))
    assert len(calls) == 2
    assert len(result.outcomes) == 1 and result.outcomes[0].status == 'suspicious'
    assert result.outcomes[0].hypothesis == 'argument can reach f without validation'
    from core.audit.journal import load_entries
    from core.audit.source_anchor import parse_context_source_anchor
    from core.audit.review_context_inputs import context_inputs_current
    entries = load_entries(out, fresh=True)
    bound = [entry for entry in entries if parse_context_source_anchor(entry.source_hash)]
    assert result.total_cost_usd == pytest.approx(0.4), "completed calls booked exactly once"
    if drift:
        assert not bound
    else:
        assert bound and bound[-1].verdict == 'suspicious'
        dependencies = bound[-1].review_claims['source_inputs']
        assert {row['file'] for row in dependencies['sources']} == {'unit.py', 'caller.py'}
        assert context_inputs_current(dependencies, target)[0]
        assert result.outcomes[0].review_result['review_claims']['source_inputs'] == dependencies
        (target / 'caller.py').write_text('def caller(n):\n    return f(n + 5)\n')
        assert not context_inputs_current(dependencies, target)[0]
    trace = json.loads((out / 'knowledge-results.json').read_text())
    assert trace['requests'] == [] and len(trace['caller_context_requests']) == 1
    assert trace['units'][0]['cycle']['started'] == 1
    assert trace['units'][0]['all_model_calls'] == 2
    completed = [e for e in trace['events'] if e['event'] == 'continuation_completed']
    if drift:
        assert not completed
        assert any(e['event'] == 'continuation_publication_refused' for e in trace['events'])
    else:
        assert len(completed) == 1
        assert completed[0]['delivered_request_ids'] == [trace['caller_context_requests'][0]['request_id']]
        assert trace['caller_context_requests'][0]['processing']['adjudication'] == 'unverified'


def test_partial_request_set_discloses_missing_code_in_same_review(tmp_path):
    runtime, ctx, request = case(tmp_path)
    request['caller_context_requests'].append({'file': 'missing.py', 'function': 'other',
        'line_start': 1, 'reason': 'An unobserved caller must stay unknown'})
    runtime._register_caller_requests(runtime._origin(ctx), request)
    reservation, = runtime.ready_continuations(admission=lambda: True)
    assert len(reservation.packet.caller_contexts) == 1
    assert runtime.enrich_context(ctx, reservation)
    prompt = format_context_for_prompt(ctx)
    assert 'return f(n)' in prompt and 'missing.py' in prompt
    assert 'caller_span_unavailable' in prompt
    delivered = ctx['caller_context_delivery']
    assert [record['delivered'] for record in delivered] == [True, False]
    assert runtime.complete(reservation, ctx)
    assert not runtime.ready_continuations(admission=lambda: True)


def test_reference_and_caller_code_share_one_round_and_call_allowance(tmp_path):
    from core.audit.caller_review_context import (
        register_caller_context_requests, resolve_caller_context, validate_caller_context,
    )
    from core.audit.knowledge_requests import KnowledgeOrigin, register_requests
    from core.audit.refutation_source import capture_source_identity
    from core.audit.review_cycle import KnowledgeCycle
    from core.language_reference import ReferenceContext, lookup

    (tmp_path / 'unit.c').write_text('int f(int n) { return n + 1; }\n')
    # This is a source/context coalescer test, not a verified call-edge claim.
    (tmp_path / 'caller.py').write_text('def caller(n):\n    return f(n)\n')
    origin = KnowledgeOrigin('source-pass', 'unit.c', 'f', 1, 1,
                             capture_source_identity(tmp_path, 'unit.c'))
    knowledge = register_requests({'language_reference_requests': [{'topic': 'integer promotion'}]}, origin)
    callers = register_caller_context_requests({'caller_context_requests': [{
        'file': 'caller.py', 'function': 'caller', 'line_start': 1, 'reason': 'Inspect this related code',
    }]}, origin)
    inventory = {'files': [{'path': 'caller.py', 'items': [{
        'name': 'caller', 'kind': 'function', 'line_start': 1, 'line_end': 2,
    }]}]}
    cycle = KnowledgeCycle(origin, knowledge, deadline=100, window=0,
        max_continuations=1, max_model_calls=2, admit_study=lambda answer: (False, 'unused'),
        admit_caller_context=lambda answer: validate_caller_context(answer, tmp_path))
    assert cycle.add_caller_requests(callers.accepted)
    request = knowledge.accepted[0]
    reference = lookup(request.request_id, request.subject, ReferenceContext('c'))
    assert reference.entries and cycle.reference(reference, now=0)
    answer = resolve_caller_context(callers.accepted[0], tmp_path, inventory)
    assert answer.material is not None and cycle.caller_context(answer, now=0)
    packet = cycle.reserve(now=1, current_source=origin.source_identity,
                           admission=lambda: True, all_model_calls=1)
    assert packet is not None and packet.references == (reference,) and packet.caller_contexts == (answer,)
    assert cycle.complete(packet.pass_id, (reference.request_id, answer.request_id))
    assert not cycle.reserve(now=2, current_source=origin.source_identity,
                             admission=lambda: True, all_model_calls=2)
    assert cycle.state_record()['started'] == 1


def test_later_validation_callback_cannot_invalidate_an_earlier_caller(tmp_path, monkeypatch):
    runtime, ctx, request = case(tmp_path)
    (tmp_path / 'other.py').write_text('def other(n):\n    return f(n)\n')
    runtime._caller_inventory['files'].append({'path': 'other.py', 'items': [{
        'name': 'other', 'kind': 'function', 'line_start': 1, 'line_end': 2,
    }]})
    request['caller_context_requests'].append({'file': 'other.py', 'function': 'other',
        'line_start': 1, 'reason': 'Inspect another related function'})
    runtime._register_caller_requests(runtime._origin(ctx), request)
    reservation, = runtime.ready_continuations(admission=lambda: True)
    original = runtime._admit_caller_context

    def invalidate_first_after_second(answer):
        verdict = original(answer)
        if answer.material.file == 'other.py':
            (tmp_path / 'caller.py').write_text('def caller(n):\n    return f(n + 9)\n')
        return verdict

    monkeypatch.setattr(runtime, '_admit_caller_context', invalidate_first_after_second)
    assert not runtime.can_publish(reservation)
    assert any(e.get('reason') == 'caller_source_changed_after_admission' for e in runtime.events())
    assert runtime.fail(reservation, 'endpoint_changed')


def test_panel_delivery_credits_only_the_selected_invocation(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context
    from threading import Barrier

    runtime, ctx, request = case(tmp_path)
    runtime._register_caller_requests(runtime._origin(ctx), request)
    reservation, = runtime.ready_continuations(admission=lambda: True, required_calls=2)
    assert runtime.enrich_context(ctx, reservation)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out')
    barrier = Barrier(2)
    monkeypatch.setattr('core.audit.llm_review._prompt_budget',
                        lambda _ctx, system: 100 if system == 'small' else 100000)
    returned = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            barrier.wait(timeout=10)
            # A model cannot assert another member's actual fitting.
            return StructuredResponse(result={'status': 'clean', 'body': 'scripted assessment',
                'caller_context_delivery': [{'request_id': runtime.caller_requests()[0].request_id,
                                             'delivered': True}]}, raw='', cost=0, model='scripted')

    small = make_review_fn(Client(), system_prompt='small', escalate_clean=False)
    large = make_review_fn(Client(), system_prompt='large', escalate_clean=False)

    def panel(shared, cfg):
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(copy_context().run, small, shared, cfg)
            b = pool.submit(copy_context().run, large, shared, cfg)
            first, second = a.result(timeout=15), b.result(timeout=15)
        returned.extend((first, second))
        # Reproduce an overwrite by the other renderer deterministically.
        shared['caller_context_delivery'] = second.review_result['caller_context_delivery']
        return first

    panel._knowledge_observed_client_contract = True
    selected = runtime.wrap_review(panel)(ctx, config)
    assert selected.review_result['caller_context_delivery'][0]['delivered'] is False
    assert returned[1].review_result['caller_context_delivery'][0]['delivered'] is True
    assert runtime.complete(reservation, ctx, published_status='suspicious', reason='prior_retained')
    completed = [e for e in runtime.events() if e['event'] == 'continuation_completed']
    assert completed[-1]['delivered_request_ids'] == []
    rows = [e for e in runtime.events() if e['event'] == 'review_prompt_context'][-1]['records']
    assert rows and all(not row['delivered'] for row in rows if row['field'] == 'caller_context_delivery')


@pytest.mark.parametrize("multi_model", [False, True], ids=["self-consistency", "cross-model"])
def test_panel_keeps_nonselected_caller_dependency_without_delivery_credit(tmp_path, monkeypatch, multi_model):
    from threading import Lock

    runtime, ctx, request = case(tmp_path)
    runtime._register_caller_requests(runtime._origin(ctx), request)
    reservation, = runtime.ready_continuations(admission=lambda: True, required_calls=2)
    assert runtime.enrich_context(ctx, reservation)
    monkeypatch.setattr('core.audit.llm_review._prompt_budget',
                        lambda _ctx, system: 100 if system == 'small' else 100000)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out', review_passes=2,
                                    multi_model=multi_model, models=['small', 'large'], adversarial=False)

    class Client:
        def __init__(self, large):
            self.large = large
        def generate_structured(self, prompt, schema, **kwargs):
            if self.large:
                assert 'return f(n)' in prompt
                payload = {'status': 'clean', 'body': 'Secondary assessment',
                    'hypotheses': [{'mechanism': 'secondary caller-dependent concern', 'confidence': 'medium'}]}
            else:
                assert 'return f(n)' not in prompt
                payload = {'status': 'suspicious', 'body': 'Primary independent concern',
                           'hypothesis': 'primary concern'}
            return StructuredResponse(result=payload, raw='', cost=0, model='scripted')

    small = make_review_fn(Client(False), system_prompt='small', escalate_clean=False)
    large = make_review_fn(Client(True), system_prompt='large', escalate_clean=False)
    config.review_fns_by_model = {'small': small, 'large': large}
    lock, remaining = Lock(), [small, large]

    def sample(context, cfg):
        with lock:
            fn = remaining.pop(0)
        return fn(context, cfg)

    sample._knowledge_observed_client_contract = True
    outcome = orch._multi_pass_review(runtime.wrap_review(sample), ctx, config, 2,
                                      knowledge_runtime=runtime)
    assert outcome.review_result['caller_context_delivery'][0]['delivered'] is False
    if not multi_model:
        assert any(h['mechanism'] == 'secondary caller-dependent concern' for h in outcome.hypotheses)
    sources = outcome.review_result['review_claims']['source_inputs']['sources']
    assert {row['file'] for row in sources} == {'unit.py', 'caller.py'}
    assert runtime.complete(reservation, ctx, published_status=outcome.status)


def test_malformed_caller_reason_cannot_poison_sibling_artifacts(tmp_path):
    runtime, ctx, request = case(tmp_path)
    valid = request['caller_context_requests'][0]
    valid['reason'] = 'café 東京 😀\nDoes this caller validate n?'
    request['caller_context_requests'].insert(0, {**valid, 'reason': chr(0xD800)})
    try:
        runtime._register_caller_requests(runtime._origin(ctx), request)
        out = tmp_path / 'artifacts'
        out.mkdir()
        runtime.write_artifacts(out)
        payload = json.loads((out / 'knowledge-results.json').read_text(encoding='utf-8'))
        assert len(payload['caller_context_requests']) == 1
        assert payload['caller_context_requests'][0]['reason'] == valid['reason']
        assert any(row.get('reason') == 'invalid_request_fields'
                   for event in payload['events'] for row in event.get('rejected', []))
    finally:
        runtime.close()


@pytest.mark.parametrize('corruption', [None, 'request_id', 'sha256', 'source_version', 'missing'])
def test_caller_publication_scope_requires_the_owned_delivery_binding(tmp_path, corruption):
    runtime, ctx, request = case(tmp_path)
    runtime._register_caller_requests(runtime._origin(ctx), request)
    reservation, = runtime.ready_continuations(admission=lambda: True)
    assert runtime.enrich_context(ctx, reservation)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out')

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            assert 'return f(n)' in prompt
            return StructuredResponse(result={'status': 'clean', 'body': 'Scripted local assessment'},
                                      raw='', cost=0, model='scripted')

    rendered_review = make_review_fn(Client(), escalate_clean=False)

    def review(context, cfg):
        outcome = rendered_review(context, cfg)
        rows = outcome.review_result['caller_context_delivery']
        assert rows[0]['delivered'] is True
        if corruption == 'request_id':
            rows[0]['request_id'] = 'unowned-request'
        elif corruption in ('sha256', 'source_version'):
            rows[0]['source_materials'][0][corruption] = ('0' * 64 if corruption == 'sha256' else [0])
        elif corruption == 'missing':
            del outcome.review_result['caller_context_delivery']
        return outcome

    review._knowledge_observed_client_contract = True
    try:
        outcome = runtime.wrap_review(review)(ctx, config)
        scope = runtime.publication_input_scope(reservation, outcome)
        unbound = [event for event in runtime.events() if event['event'] == 'review_inputs_unbound']
        if corruption is None:
            assert scope is not None and scope.current(tmp_path)
            assert {source.file for source in scope.inputs} == {'caller.py'}
            assert not unbound
        else:
            assert scope is None
            assert len(unbound) == 1
            assert unbound[0]['reason'] == 'delivered_input_binding_unavailable'
    finally:
        runtime.fail(reservation, 'local_binding_control')
        runtime.close()


@pytest.mark.parametrize('delivered', [False, True], ids=['omitted', 'fitted'])
@pytest.mark.parametrize('failed', [False, True], ids=['completed', 'failed'])
def test_returned_caller_receipt_mutation_cannot_rewrite_retained_delivery(tmp_path, monkeypatch, delivered, failed):
    from copy import deepcopy

    runtime, ctx, request = case(tmp_path)
    runtime._register_caller_requests(runtime._origin(ctx), request)
    reservation, = runtime.ready_continuations(admission=lambda: True)
    assert runtime.enrich_context(ctx, reservation)
    monkeypatch.setattr('core.audit.llm_review._prompt_budget', lambda *_: 100000 if delivered else 100)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out')

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            assert ('return f(n)' in prompt) is delivered
            return StructuredResponse(result={'status': 'clean', 'body': 'Scripted local assessment'},
                                      raw='', cost=0, model='scripted')

    try:
        outcome = runtime.wrap_review(make_review_fn(Client(), escalate_clean=False))(ctx, config)
        row, = outcome.review_result['caller_context_delivery']
        original = deepcopy(row)
        assert original['delivered'] is delivered
        row['delivered'] = not delivered
        row['request_id'] = 'replacement-request'
        row['source_materials'][0]['sha256'] = '0' * 64
        row['source_materials'][0]['source_version'][0] = -1
        if failed:
            assert runtime.fail(reservation, 'scripted_review_failure', ctx)
        else:
            assert runtime.complete(reservation, ctx, published_status=outcome.status)
        prompt_event = [event for event in runtime.events() if event['event'] == 'review_prompt_context'][-1]
        assert prompt_event['records'] == [{'field': 'caller_context_delivery', **original}]
        terminal = [event for event in runtime.events()
                    if event['event'] in ('continuation_completed', 'continuation_failed')][-1]
        if failed:
            assert terminal['published_status'] == '' and 'delivered_request_ids' not in terminal
        else:
            assert terminal['delivered_request_ids'] == ([original['request_id']] if delivered else [])
        config.out_dir.mkdir()
        runtime.write_artifacts(config.out_dir)
        payload = json.loads((config.out_dir / 'knowledge-results.json').read_text(encoding='utf-8'))
        processing = payload['caller_context_requests'][0]['processing']
        assert processing['state'] == ('review_completed' if delivered and not failed else 'deferred')
        assert processing['adjudication'] == 'unverified'
        assert not runtime._caller_deliveries
    finally:
        runtime.close()
