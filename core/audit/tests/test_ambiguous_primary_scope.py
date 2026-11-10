"""A scalar mechanism cannot choose between conflicting structured premises."""

from copy import deepcopy

import pytest

from core.audit import orchestrator as orch
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.fixture(autouse=True)
def owned_shutdown():
    with isolated_audit_shutdown(orch):
        yield


def case(tmp_path):
    root = tmp_path / 'target'
    root.mkdir()
    (root / 'source.c').write_text('int f(int n) { return n; }\n')
    out = tmp_path / 'out'
    out.mkdir()
    variants = [
        {'mechanism': 'range interpretation', 'confidence': 'high', 'counter_scope': 'local',
         'assumed_property': 'local declaration'},
        {'mechanism': 'range interpretation', 'confidence': 'medium', 'counter_scope': 'cross_function',
         'assumed_property': 'caller declaration'},
    ]
    outcome = orch.ReviewOutcome(file='source.c', function='f', line=1, status='suspicious', body='review',
        hypothesis='range interpretation', hypotheses=variants,
        review_result={'hypothesis': 'range interpretation', 'cwe': 'CWE-20'})
    config = orch.OrchestratorConfig(target_path=root, out_dir=out, zero_dispatch_resweep_seconds=5)
    result = orch.OrchestratorResult(outcomes=[outcome], suspicious=1)
    return outcome, result, config


@pytest.mark.parametrize('reverse', [False, True])
def test_conflicting_material_is_not_selected_by_input_order(tmp_path, reverse):
    outcome, _, _ = case(tmp_path)
    if reverse:
        outcome.hypotheses.reverse()
    assert orch._primary_hypothesis_entry(outcome, outcome.hypothesis) is None


def test_equivalent_duplicates_and_absent_claim_remain_distinct_from_ambiguity(tmp_path):
    outcome, _, _ = case(tmp_path)
    first = outcome.hypotheses[0]
    outcome.hypotheses = [first, {**first, 'confidence': 'low'}]
    outcome.review_result['hypotheses'] = deepcopy(outcome.hypotheses)
    assert orch._primary_hypothesis_entry(outcome, outcome.hypothesis) is first
    assert orch._primary_hypothesis_entry(outcome, 'other concern') == {}


def forbidden(*args, **kwargs):
    pytest.fail('ambiguous scalar claim reached dispatch or source acquisition')


@pytest.mark.parametrize('lane', ['sweep', 'promote', 'synthesis', 'resweep'])
def test_ambiguous_primary_defers_before_source_or_provider_work(tmp_path, monkeypatch, lane):
    from core.audit.record import load_audit_log

    outcome, result, config = case(tmp_path)
    monkeypatch.setattr(orch, '_read_raw_source', forbidden)
    monkeypatch.setattr(orch, '_hypothesis_to_tool_chain', forbidden)
    monkeypatch.setattr(orch, '_run_tool_chain', forbidden)
    monkeypatch.setattr(orch, '_bind_synthesis_request', forbidden)
    if lane == 'sweep':
        outcome.status = 'finding'
        deferred = orch._sweep_validate(outcome, config)
        assert deferred.status == 'suspicious'
        assert 'ambiguous claim material' in deferred.body
    elif lane == 'promote':
        assert orch._promote_suspicious_one(result, config, 0, outcome) is None
    elif lane == 'synthesis':
        orch._synthesize_unmapped_suspicious(result, config, 0, outcome,
                                            outcome.hypothesis, 'CWE-20', 'fixture source')
        assert result.ondemand_synthesized == 0
    else:
        orch._resweep_zero_dispatch_suspicious(result, config)
    assert not outcome.tools_dispatched and not outcome.claim_refutations
    assert result.findings == 0 and result.total_cost_usd == 0
    events = load_audit_log(config.out_dir)
    if lane == 'resweep':
        assert any(e.get('skip_reason') == 'ambiguous-claim-material' for e in events)
    else:
        assert any(e.get('action') == 'claim_material_deferred' and e.get('adjudication') == 'unverified'
                   for e in events)


@pytest.mark.parametrize('mutation', ['none', 'original-conflict', 'candidate-conflict',
                                     'original-change', 'candidate-change'])
def test_synthesis_rechecks_structured_material_after_callback(tmp_path, monkeypatch, mutation):
    from core.audit import checker_synthesis
    from core.audit.checker_synthesis import OnDemandSynthesisResult

    outcome, result, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    original = deepcopy(outcome.hypotheses)
    calls = []

    def synthesize(candidate, config, **kwargs):
        calls.append(candidate)
        if mutation != 'none':
            target = outcome if mutation.startswith('original') else candidate
            if mutation.endswith('conflict'):
                target.hypotheses.append({**target.hypotheses[0], 'assumed_property': 'different declaration'})
            else:
                target.hypotheses[0]['assumed_property'] = 'different declaration'
        # This is an injected already-confirmed receipt, not native checker proof.
        return OnDemandSynthesisResult(confirmed=True, stamp='semgrep:synth-fixture',
                                       cwe='CWE-20', cost_usd=0.02)

    monkeypatch.setattr(checker_synthesis, 'synthesize_verification_rule', synthesize)
    monkeypatch.setattr(checker_synthesis, 'ondemand_synthesis_refusal_reason', lambda *a, **kw: None)
    monkeypatch.setattr(orch, '_synth_receipt_promotion_block_reason', lambda *a, **kw: None)
    monkeypatch.setattr(orch, '_guard_blocks_promotion', lambda *a, **kw: None)
    source = (config.target_path / outcome.file).read_text()
    orch._synthesize_unmapped_suspicious(result, config, 0, outcome, outcome.hypothesis, 'CWE-20', source)
    assert len(calls) == 1
    assert result.ondemand_synthesized == 1
    assert result.total_cost_usd == pytest.approx(0.02)
    assert result.outcomes[0].status == ('finding' if mutation == 'none' else 'suspicious')
    if mutation == 'none':
        assert outcome.hypotheses == original
    else:
        assert result.findings == 0 and result.sweep_promoted == 0
        assert outcome.review_result['claim_material_deferred']['reason'] == 'claim-material-revised'
