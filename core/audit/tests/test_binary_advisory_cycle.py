"""Typed binary advisory scheduling preserves the existing unit allowance.

These are coordinator-component controls, not live Runtime/publication proof.
"""
from dataclasses import replace

import pytest

from core.audit.knowledge_requests import KnowledgeBatch, register_requests
from core.audit.review_cycle import KnowledgeCycle
from core.audit.tests.test_binary_review_origin import binary_inputs as binary_inputs


def _cycle(binary_inputs):
    target, runtime, context = binary_inputs
    origin = runtime._origin(context())
    cycle = KnowledgeCycle(origin, KnowledgeBatch((), ()), deadline=10, window=0,
                           admit_study=lambda *_: pytest.fail('binary advisory entered source study'))
    assert cycle.context_delta('advisory-first', now=0, kind='disagreement')
    return cycle, origin


def test_matching_binary_view_reserves_only_external_advisory_context(binary_inputs):
    cycle, origin = _cycle(binary_inputs)
    admissions = []
    packet = cycle.reserve(now=1, current_source=None, current_binary=origin.binary_identity,
        admission=lambda: admissions.append(1) or True, all_model_calls=1)
    assert packet is not None
    assert packet.external_context_ids == ('advisory-first',)
    assert not packet.references and not packet.explanations and not packet.caller_contexts
    assert cycle.started == 1 and admissions == [1]
    assert cycle.complete(packet.pass_id, packet.external_context_ids)
    assert cycle.reserve(now=2, current_source=None, current_binary=origin.binary_identity,
                         admission=lambda: pytest.fail('same delta repeated admission'), all_model_calls=2) is None


@pytest.mark.parametrize('change', ['view', 'module', 'epoch', 'address', 'size', 'representation', 'absent'])
def test_missing_or_changed_binary_input_never_consumes_admission(binary_inputs, change):
    cycle, origin = _cycle(binary_inputs)
    identity = origin.binary_identity
    if change == 'view':
        identity = replace(identity, view_sha256='0'*64)
    elif change == 'module':
        identity = replace(identity, module_sha256='0'*64)
    elif change == 'epoch':
        identity = replace(identity, module_version=(*identity.module_version[:-1], identity.module_version[-1]+1))
    elif change == 'address':
        identity = replace(identity, address=8192)
    elif change == 'size':
        identity = replace(identity, size=64)
    elif change == 'representation':
        identity = replace(identity, representation='disassembly')
    else:
        identity = None
    assert cycle.reserve(now=1, current_source=None, current_binary=identity,
        admission=lambda: pytest.fail('foreign input consumed admission'), all_model_calls=1) is None
    assert cycle.started == 0


@pytest.mark.parametrize('calls,width,expected', [(1,1,True),(4,2,True),(5,2,False),(6,1,False),(None,1,False)])
def test_binary_advisory_uses_existing_total_call_limit(binary_inputs, calls, width, expected):
    cycle, origin = _cycle(binary_inputs)
    admissions = []
    packet = cycle.reserve(now=1, current_source=None, current_binary=origin.binary_identity,
        admission=lambda: admissions.append(1) or True, all_model_calls=calls, required_calls=width)
    assert (packet is not None) is expected
    assert len(admissions) == int(expected)


def test_binary_advisory_failures_still_consume_two_round_allowance(binary_inputs):
    cycle, origin = _cycle(binary_inputs)
    for index in range(2):
        if index:
            assert cycle.context_delta(f'advisory-{index}', now=index, kind='disagreement')
        packet = cycle.reserve(now=index+1, current_source=None, current_binary=origin.binary_identity,
                              admission=lambda:True, all_model_calls=index+1)
        assert packet is not None
        assert cycle.failed(packet.pass_id, reason='captured_failure')
    assert cycle.context_delta('third', now=3, kind='disagreement')
    assert cycle.reserve(now=4, current_source=None, current_binary=origin.binary_identity,
        admission=lambda:pytest.fail('third round consumed admission'), all_model_calls=3) is None
    assert cycle.started == 2


@pytest.mark.parametrize('source_requests', [False, True])
def test_binary_coordinator_does_not_admit_source_study_or_other_producers(binary_inputs, source_requests):
    target, runtime, context = binary_inputs
    origin = runtime._origin(context())
    batch = (register_requests({'language_reference_requests':[{'topic':'integer shifts',
        'needed_for':'read view','priority':'normal'}]},origin) if source_requests else KnowledgeBatch((),()))
    cycle = KnowledgeCycle(origin, batch, deadline=10, window=0,
                           admit_study=lambda *_:pytest.fail('source study entered'))
    assert cycle.context_delta('unsupported',now=0,kind='disagreement' if source_requests else 'callee_contract')
    assert cycle.reserve(now=1,current_source=None,current_binary=origin.binary_identity,
        admission=lambda:pytest.fail('unsupported binary producer admitted'),all_model_calls=1) is None


def test_source_cycle_cannot_substitute_binary_identity(binary_inputs, tmp_path):
    from core.audit.knowledge_requests import KnowledgeOrigin
    from core.audit.refutation_source import capture_source_identity
    (tmp_path/'unit.c').write_text('int f(void) { return 1; }\n')
    source = capture_source_identity(tmp_path, 'unit.c')
    assert source is not None
    origin = KnowledgeOrigin('owned', 'unit.c', 'f', 1, 1, source)
    cycle = KnowledgeCycle(origin, KnowledgeBatch((),()), deadline=10, window=0,
                           admit_study=lambda *_:pytest.fail('source study entered'))
    assert cycle.context_delta('source-advisory',now=0,kind='disagreement')
    binary_cycle, binary_origin = _cycle(binary_inputs)
    assert cycle.reserve(now=1,current_source=source,current_binary=binary_origin.binary_identity,
        admission=lambda:pytest.fail('mixed domain admitted'),all_model_calls=1) is None
    assert cycle.reserve(now=1,current_source=source,admission=lambda:True,all_model_calls=1) is not None


@pytest.mark.parametrize('expired', [False, True])
def test_binary_deadline_and_shared_refusal_do_not_consume_round(binary_inputs, expired):
    cycle, origin = _cycle(binary_inputs)
    called = []
    packet = cycle.reserve(now=10 if expired else 1,current_source=None,current_binary=origin.binary_identity,
        admission=lambda:called.append(1) or False,all_model_calls=1)
    assert packet is None and cycle.started == 0
    assert called == ([] if expired else [1])
