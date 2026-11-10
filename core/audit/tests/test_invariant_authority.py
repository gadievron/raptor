"""Conditional invariant transitions never clear source-level entry claims."""

from types import SimpleNamespace

import pytest

from core.audit import evidence_grade, sweep
from core.audit.refutation_source import SourceIdentity
from core.audit.smt_evidence import is_diagnostic_smt_rule, is_non_refuting_smt_rule
from core.audit.verification_results import ClaimRefutation, ProbeOutcome, ToolChainResult, claims_refuted

SCOPE = {'file': 'unit.c', 'function': 'Read', 'line_start': 1,
         'hypothesis': 'Len can exceed Size at function entry'}
IDENTITY = SourceIdentity('owned-source', (1, 2, 3))


@pytest.mark.parametrize('suffix', ['', ':witness', ':model', ':unknown'])
@pytest.mark.parametrize('fallback', [False, True])
def test_invariant_models_remain_diagnostic_in_every_classifier(suffix, fallback, monkeypatch):
    from core.audit.orchestrator import _promotion_grade_receipt
    if fallback:
        monkeypatch.setattr(evidence_grade, '_channel_detection_classifier', lambda namespace: None)
    stamp = 'smt:invariant-preservation' + suffix
    assert is_diagnostic_smt_rule(stamp) and is_non_refuting_smt_rule(stamp)
    assert sweep.is_detection_rule_id(stamp)
    assert not evidence_grade.is_verification_evidence(stamp)
    assert not _promotion_grade_receipt(stamp)
    # Source arithmetic receipts retain their existing authority.
    assert evidence_grade.is_verification_evidence('smt:check-overflow')
    assert evidence_grade.is_verification_evidence('smt:check-overflow:witness')


@pytest.mark.parametrize('tool', ['smt', 'smt_invariant', 'legacy-dispatch-alias'])
@pytest.mark.parametrize('suffix', ['', ':witness'])
def test_legacy_conditional_refutations_cannot_regain_claim_authority(tool, suffix):
    stamp = 'smt:invariant-preservation' + suffix
    check = ProbeOutcome(tool, 'refuted', stamp, 'preserved assuming the invariant before each step')
    receipt = ClaimRefutation(**SCOPE, source_identity=IDENTITY, checks=(check,))
    assert not receipt.matches(**SCOPE, source_identity=IDENTITY)
    outcome = SimpleNamespace(file=SCOPE['file'], function=SCOPE['function'], line=1,
                              claim_refutations=(receipt,))
    assert not claims_refuted(outcome, [SCOPE['hypothesis']], source_identity=IDENTITY)
    chain = ToolChainResult(**SCOPE, source_identity=IDENTITY)
    chain.observe(tool, 'refuted', stamp)
    assert chain.refutation(**SCOPE) is None
    assert chain.refutation_record(**SCOPE) is None


def test_invariant_dispatch_alias_cannot_mislabel_a_refutation_as_another_rule():
    receipt = ClaimRefutation(**SCOPE, source_identity=IDENTITY,
                              checks=(ProbeOutcome('smt_invariant', 'refuted', 'legacy-invariant'),))
    assert not receipt.matches(**SCOPE, source_identity=IDENTITY)


def test_specific_source_arithmetic_refutation_still_has_its_existing_role():
    chain = ToolChainResult(**SCOPE, source_identity=IDENTITY)
    chain.observe('smt', 'refuted', 'smt:check-overflow', 'complete source arithmetic obligation is unsatisfiable')
    receipt = chain.refutation(**SCOPE)
    assert receipt is not None and receipt.matches(**SCOPE, source_identity=IDENTITY)


@pytest.mark.slow
def test_actual_worker_preservation_cannot_refute_a_false_entry_invariant(tmp_path):
    pytest.importorskip('tree_sitter_c')
    from core.audit.orchestrator import OrchestratorConfig, TierCounters, _run_tool_chain
    source = 'int Read(int Len,int Size){return Len;}\n'
    (tmp_path / 'unit.c').write_text(source)
    counters = {'smt_invariant': TierCounters()}
    inconclusive = set()
    chain = _run_tool_chain([{'type': 'smt_invariant', 'config': {'invariant': 'Len <= Size'}}],
                             config=OrchestratorConfig(target_path=tmp_path, out_dir=None, integer_abi='lp64'),
                             file_path='unit.c', function_name='Read', source=source,
                             hypothesis=SCOPE['hypothesis'], line_start=1,
                             tier_counters=counters, inconclusive_types=inconclusive)
    assert chain.source_identity is not None
    assert 2 > 1  # A valid int entry assignment violates the proposed invariant.
    assert chain == [] and len(chain.outcomes) == 1
    assert chain.outcomes[0].verdict == 'inconclusive'
    assert 'base case not checked' in chain.outcomes[0].reason
    assert chain.refutation(**SCOPE) is None and chain.refutation_record(**SCOPE) is None
    assert counters['smt_invariant'].inconclusive == 1 and counters['smt_invariant'].refuted == 0
    assert inconclusive == {'smt_invariant'}


@pytest.mark.slow
def test_actual_worker_violation_keeps_the_conditional_observation(tmp_path):
    pytest.importorskip('tree_sitter_c')
    pytest.importorskip('z3')
    from core.audit.orchestrator import OrchestratorConfig, TierCounters, _run_tool_chain, _promotion_grade_receipt
    source = 'void Grow(int len,int size,int n){len += n;}\n'
    (tmp_path / 'unit.c').write_text(source)
    counters = {'smt_invariant': TierCounters()}
    chain = _run_tool_chain([{'type': 'smt_invariant', 'config': {'invariant': 'len <= size'}}],
                             config=OrchestratorConfig(target_path=tmp_path, out_dir=None, integer_abi='lp64'),
                             file_path='unit.c', function_name='Grow', source=source,
                             hypothesis='the mutation can violate len <= size', line_start=1,
                             tier_counters=counters)
    assert chain.source_identity is not None
    assert chain == ['smt:invariant-preservation'] and counters['smt_invariant'].confirmed == 1
    assert chain.outcomes[0].verdict == 'confirmed'
    assert not _promotion_grade_receipt(chain[0])
