"""Text-scoped dispatch cannot choose an ambiguous structured claim."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from core.audit import orchestrator as orch
from core.audit.claim_verification import ClaimVerification
from core.testing.audit_shutdown import isolated_audit_shutdown

STRONG = 'semgrep:explicit-error-discard'


@pytest.fixture(autouse=True)
def owned_shutdown():
    with isolated_audit_shutdown(orch):
        yield


def case(tmp_path):
    (tmp_path / 'source.c').write_text('int f(int n) { return n; }\n')
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
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out, immediate_verify=True)
    result = orch.OrchestratorResult(outcomes=[outcome], suspicious=1)
    return outcome, result, config


def forbidden(*args, **kwargs):
    pytest.fail('ambiguous material reached a text-only dispatch boundary')


def test_ihv_defers_before_correlation_routing_or_provider_work(tmp_path, monkeypatch):
    outcome, result, config = case(tmp_path)
    original = deepcopy(outcome.hypotheses)
    monkeypatch.setattr(orch, '_correlated_mech_detector_tool', forbidden)
    monkeypatch.setattr(orch, '_get_llm_client', forbidden)
    monkeypatch.setattr(orch, '_run_tool_chain', forbidden)
    deferred = orch._verify_hypotheses_immediate(outcome, config, result)
    assert deferred.status == 'suspicious'
    assert deferred.hypotheses == original
    assert not deferred.tools_dispatched
    assert not deferred.review_result.get('immediate_verified')
    assert deferred.review_result['claim_material_deferred']['reason'] == 'ambiguous-claim-material'


def test_ambiguous_secondary_defers_before_shared_source_read(tmp_path, monkeypatch):
    outcome, result, config = case(tmp_path)
    outcome.hypothesis = outcome.review_result['hypothesis'] = 'independent primary'
    monkeypatch.setattr(orch, '_read_raw_source', forbidden)
    monkeypatch.setattr(orch, '_hypothesis_to_tool_chain', forbidden)
    orch._dispatch_secondary_hypotheses(result, config)
    assert result.findings == result.secondary_confirmed == 0
    assert outcome.review_result['claim_material_deferred']['phase'] == 'secondary_sweep'


def test_bound_synthesis_defers_before_reserving_an_attempt(tmp_path, monkeypatch):
    outcome, result, config = case(tmp_path)
    monkeypatch.setattr(orch, '_bind_synthesis_request', forbidden)
    counter = SimpleNamespace(try_reserve=forbidden)
    assert orch._try_bound_ihv_synthesis(outcome, config, result, outcome.hypotheses[0],
                                        'CWE-20', 'fixture', counter) is None
    assert result.ondemand_synthesized == 0


@pytest.mark.parametrize('independent', [False, True])
def test_ambiguous_support_does_not_hide_an_independent_claim(tmp_path, independent):
    outcome, result, config = case(tmp_path)
    records = [ClaimVerification(outcome.hypotheses[0], (STRONG,))]
    if independent:
        other = {'mechanism': 'independent concern', 'confidence': 'high', 'cwe': 'CWE-20'}
        outcome.hypotheses.append(other)
        records.append(ClaimVerification(other, (STRONG,)))
    final = orch._aggregate_ihv_verdicts(outcome, result, [r.hypothesis for r in records], records, config)
    assert final.status == ('finding' if independent else 'suspicious')
    if independent:
        assert final.hypothesis == 'independent concern'
    else:
        assert final.review_result['ihv_gate_blocked'] == 'ambiguous-claim-material'


@pytest.mark.parametrize('changed', [False, True])
def test_aggregation_rechecks_material_after_context_callback(tmp_path, monkeypatch, changed):
    outcome, result, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    snapshot = ClaimVerification(outcome.hypotheses[0], (STRONG,))

    def gate(candidate, config, **kwargs):
        if changed:
            candidate.hypotheses[0]['assumed_property'] = 'different declaration'
        return None

    monkeypatch.setattr(orch, '_ihv_context_gate', gate)
    final = orch._aggregate_ihv_verdicts(outcome, result, [snapshot.hypothesis], [snapshot], config)
    assert final.status == ('suspicious' if changed else 'finding')
    if changed:
        assert final.review_result['ihv_gate_blocked'] == 'claim-material-revised'


@pytest.mark.parametrize('mutation', ['none', 'chain', 'guard', 'chain-delete', 'guard-delete', 'chain-rename', 'guard-rename'])
def test_secondary_rechecks_owned_material_snapshot(tmp_path, monkeypatch, mutation):
    outcome, result, config = case(tmp_path)
    outcome.hypothesis = outcome.review_result['hypothesis'] = 'independent primary'
    outcome.hypotheses = outcome.hypotheses[:1]
    calls = []

    def chain(*args, **kwargs):
        calls.append('chain')
        if mutation == 'chain':
            outcome.hypotheses[0]['assumed_property'] = 'different declaration'
        elif mutation == 'chain-delete':
            outcome.hypotheses = []
        elif mutation == 'chain-rename':
            outcome.hypotheses = [{**outcome.hypotheses[0], 'mechanism': 'different concern'}]
        return [STRONG]  # Injected receipt: this tests admission, not checker truth.

    def guard(*args, **kwargs):
        if mutation == 'guard':
            outcome.hypotheses[0]['assumed_property'] = 'different declaration'
        elif mutation == 'guard-delete':
            outcome.hypotheses = []
        elif mutation == 'guard-rename':
            outcome.hypotheses = [{**outcome.hypotheses[0], 'mechanism': 'different concern'}]
        return None

    monkeypatch.setattr(orch, '_hypothesis_to_tool_chain', lambda *a, **kw: [{'type': 'semgrep'}])
    monkeypatch.setattr(orch, '_run_tool_chain', chain)
    monkeypatch.setattr(orch, '_guard_blocks_promotion', guard)
    monkeypatch.setattr(orch, '_synthesize_unmapped_suspicious', forbidden)
    orch._dispatch_secondary_hypotheses(result, config)
    assert calls == ['chain']
    assert result.outcomes[0].status == ('finding' if mutation == 'none' else 'suspicious')
    if mutation != 'none':
        assert result.secondary_confirmed == result.findings == 0
        assert outcome.review_result['claim_material_deferred']['reason'] == 'claim-material-revised'


@pytest.mark.parametrize('mutation', ['original-delete', 'candidate-delete', 'original-replace',
                                     'candidate-replace', 'original-rename', 'candidate-rename'])
def test_context_cannot_turn_a_declared_claim_into_legacy_absence(tmp_path, monkeypatch, mutation):
    outcome, result, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    snapshot = ClaimVerification(outcome.hypotheses[0], (STRONG,))

    def gate(candidate, config, **kwargs):
        target = outcome if mutation.startswith('original') else candidate
        if mutation.endswith('delete'):
            target.hypotheses = []
        elif mutation.endswith('rename'):
            target.hypotheses = [{**target.hypotheses[0], 'mechanism': 'different concern'}]
        else:
            target.hypotheses = [{**target.hypotheses[0], 'assumed_property': 'different declaration'}]
        return None

    monkeypatch.setattr(orch, '_ihv_context_gate', gate)
    final = orch._aggregate_ihv_verdicts(outcome, result, [snapshot.hypothesis], [snapshot], config)
    assert final.status == 'suspicious'
    assert not final.review_result.get('immediate_verified')
    assert final.review_result['ihv_gate_blocked'] == 'claim-material-revised'


def test_pipeline_admission_survives_receipt_copy_and_declaration_loss(tmp_path, monkeypatch):
    outcome, result, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    expected = orch._claim_material_admission(outcome, outcome.hypothesis)

    def correlate(*args, **kwargs):
        outcome.hypotheses = []
        return STRONG

    monkeypatch.setattr(orch, '_correlated_mech_detector_tool', correlate)
    monkeypatch.setattr(orch, '_get_llm_client', forbidden)
    final = orch._verify_hypotheses_immediate(outcome, config, result)
    assert final.status == 'suspicious'
    assert final.review_result['ihv_gate_blocked'] == 'claim-material-revised'
    assert expected is not None and expected[1]


def test_binding_callback_cannot_erase_declarations_before_attempt_reservation(tmp_path, monkeypatch):
    outcome, result, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    actual = orch._bind_synthesis_request

    def bind(*args, **kwargs):
        bound = actual(*args, **kwargs)
        assert bound is not None, 'fixture must reach a real admitted source binding'
        outcome.hypotheses = []
        return bound

    monkeypatch.setattr(orch, '_bind_synthesis_request', bind)
    counter = SimpleNamespace(try_reserve=forbidden)
    source = (config.target_path / outcome.file).read_text()
    assert orch._try_bound_ihv_synthesis(outcome, config, result, outcome.hypotheses[0],
                                        'CWE-20', source, counter) is None
    assert result.ondemand_synthesized == 0


def test_admission_metadata_is_immutable_and_retained_by_observation(tmp_path):
    outcome, _, _ = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    admission = orch._claim_material_admission(outcome, outcome.hypothesis)
    record = ClaimVerification(outcome.hypotheses[0], material_admission=admission)
    observed = record.with_observation((STRONG,))
    outcome.hypotheses[0]['assumed_property'] = 'different declaration'
    assert observed.material_admission == record.material_admission == admission
    assert observed.hypothesis['assumed_property'] == 'local declaration'
    with pytest.raises(TypeError):
        ClaimVerification(record.hypothesis, material_admission=('CWE-20', ['mutable']))


@pytest.mark.parametrize('mutation', ['none', 'delete', 'rename', 'replace'])
def test_negative_receipt_cannot_clear_a_changed_declared_claim(tmp_path, mutation):
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ClaimRefutation, ProbeOutcome

    outcome, result, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    hypothesis = deepcopy(outcome.hypotheses[0])
    admission = orch._claim_material_admission(outcome, outcome.hypothesis)
    record = ClaimVerification(hypothesis, refuted=True, material_admission=admission)
    identity = capture_source_identity(config.target_path, outcome.file)
    outcome.claim_refutations = (ClaimRefutation(outcome.file, outcome.function, outcome.line, outcome.hypothesis,
        (ProbeOutcome('semgrep', 'refuted', 'fixture-negative'),), identity),)
    if mutation == 'delete':
        outcome.hypotheses = []
    elif mutation == 'rename':
        outcome.hypotheses = [{**hypothesis, 'mechanism': 'different concern'}]
    elif mutation == 'replace':
        outcome.hypotheses = [{**hypothesis, 'assumed_property': 'different declaration'}]
    final = orch._aggregate_ihv_verdicts(outcome, result, [hypothesis], [record], config)
    assert final.status == ('clean' if mutation == 'none' else 'suspicious')
    assert final.claim_refutations == outcome.claim_refutations
    if mutation != 'none':
        assert not final.review_result.get('ihv_all_refuted')
        assert final.review_result['ihv_gate_blocked'] == 'claim-material-revised'


def test_legacy_negative_cannot_clear_declarations_lost_during_source_recheck(tmp_path, monkeypatch):
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ClaimRefutation, ProbeOutcome

    outcome, result, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    hypothesis = deepcopy(outcome.hypotheses[0])
    record = ClaimVerification(hypothesis, refuted=True)  # Untracked legacy producer.
    identity = capture_source_identity(config.target_path, outcome.file)
    outcome.claim_refutations = (ClaimRefutation(outcome.file, outcome.function, outcome.line, outcome.hypothesis,
        (ProbeOutcome('semgrep', 'refuted', 'fixture-negative'),), identity),)
    actual = orch.capture_source_identity

    def recheck(*args, **kwargs):
        outcome.hypotheses = []
        return actual(*args, **kwargs)

    monkeypatch.setattr(orch, 'capture_source_identity', recheck)
    final = orch._aggregate_ihv_verdicts(outcome, result, [hypothesis], [record], config)
    assert final.status == 'suspicious'
    assert not final.review_result.get('ihv_all_refuted')
    assert final.review_result['ihv_gate_blocked'] == 'claim-material-revised'


def test_changed_negative_cannot_escape_through_later_resolution(tmp_path, monkeypatch):
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ToolChainResult, claims_refuted

    outcome, result, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    expected = orch._claim_material_admission(outcome, outcome.hypothesis)
    identity = capture_source_identity(config.target_path, outcome.file)

    def chain(*args, **kwargs):
        proof = ToolChainResult(file=outcome.file, function=outcome.function, line_start=outcome.line,
            hypothesis=outcome.hypothesis, source_identity=identity, claim_revision=kwargs.get('claim_revision'))
        proof.observe('semgrep', 'refuted', 'fixture-negative')
        outcome.hypotheses = []
        return proof

    monkeypatch.setattr(orch, '_correlated_mech_detector_tool', lambda *a, **kw: None)
    monkeypatch.setattr(orch, '_gather_library_candidates', lambda *a, **kw: [])
    monkeypatch.setattr(orch, '_get_llm_client', lambda *a, **kw: None)
    monkeypatch.setattr(orch, '_hypothesis_to_tool_chain', lambda *a, **kw: [{'type': 'semgrep'}])
    monkeypatch.setattr(orch, '_run_tool_chain', chain)
    source = (config.target_path / outcome.file).read_text()
    final = orch._verify_hypotheses_immediate(outcome, config, result, source=source)
    assert final.status == 'suspicious' and len(final.claim_refutations) == 1
    assert not claims_refuted(final, [outcome.hypothesis], source_identity=identity)
    assert final.claim_refutations[0].material_admission == expected


def test_known_receipt_context_cannot_fall_back_to_an_untracked_duplicate(tmp_path):
    from dataclasses import replace

    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ClaimRefutation, ProbeOutcome, claims_refuted

    outcome, _, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    identity = capture_source_identity(config.target_path, outcome.file)
    admission = orch._claim_material_admission(outcome, outcome.hypothesis)
    legacy = ClaimRefutation(outcome.file, outcome.function, outcome.line, outcome.hypothesis,
                             (ProbeOutcome('semgrep', 'refuted', 'fixture-negative'),), identity)
    contextual = replace(legacy, material_admission=admission)
    assert contextual != legacy  # Admission changes cannot disappear through receipt deduplication.
    outcome.claim_refutations = (legacy, contextual)
    assert claims_refuted(outcome, [outcome.hypothesis], source_identity=identity)
    record = contextual.to_record()
    assert record['material_admission']['role'] == 'rejection_context_not_checker_scope'
    outcome.hypotheses = []
    assert not claims_refuted(outcome, [outcome.hypothesis], source_identity=identity)
    assert contextual.matches(file=outcome.file, function=outcome.function, line_start=outcome.line,
                              hypothesis=outcome.hypothesis, source_identity=identity)


def test_prior_declarations_are_required_to_use_a_contextual_negative_in_a_new_assessment(tmp_path):
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ClaimRefutation, ProbeOutcome, claims_refuted

    prior, _, config = case(tmp_path)
    prior.hypotheses = prior.hypotheses[:1]
    identity = capture_source_identity(config.target_path, prior.file)
    admission = orch._claim_material_admission(prior, prior.hypothesis)
    proof = ClaimRefutation(prior.file, prior.function, prior.line, prior.hypothesis,
                            (ProbeOutcome('semgrep', 'refuted', 'fixture-negative'),), identity,
                            material_admission=admission)
    fresh = orch.ReviewOutcome(file=prior.file, function=prior.function, line=prior.line,
                               status='clean', body='re-review', claim_refutations=(proof,))
    assert not claims_refuted(fresh, [prior.hypothesis], source_identity=identity)
    assert claims_refuted(fresh, [prior.hypothesis], source_identity=identity, claim_outcome=prior)
    assert not claims_refuted(fresh, ['another concern'], source_identity=identity, claim_outcome=prior)


def test_different_material_receipt_contexts_are_retained_and_independently_matched(tmp_path):
    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ToolChainResult, claims_refuted

    outcome, _, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    identity = capture_source_identity(config.target_path, outcome.file)
    proof = ToolChainResult(file=outcome.file, function=outcome.function, line_start=outcome.line,
                             hypothesis=outcome.hypothesis, source_identity=identity)
    proof.observe('semgrep', 'refuted', 'fixture-negative')
    for property_value in ('local declaration', 'different declaration'):
        outcome.hypotheses[0]['assumed_property'] = property_value
        admission = orch._claim_material_admission(outcome, outcome.hypothesis)
        assert orch._retain_claim_refutation(outcome, proof, config, hypothesis=outcome.hypothesis,
                                             phase='ihv', material_admission=admission)
    assert len(outcome.claim_refutations) == 2
    assert claims_refuted(outcome, [outcome.hypothesis], source_identity=identity)
    outcome.hypotheses = []
    assert not claims_refuted(outcome, [outcome.hypothesis], source_identity=identity)


@pytest.mark.parametrize('reverse', [False, True])
def test_known_absence_cannot_override_lost_nonempty_receipt_context(tmp_path, reverse):
    from dataclasses import replace

    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ClaimRefutation, ProbeOutcome, claims_refuted

    outcome, _, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    identity = capture_source_identity(config.target_path, outcome.file)
    admission = orch._claim_material_admission(outcome, outcome.hypothesis)
    declared = ClaimRefutation(outcome.file, outcome.function, outcome.line, outcome.hypothesis,
        (ProbeOutcome('semgrep', 'refuted', 'fixture-negative'),), identity, material_admission=admission)
    absent = replace(declared, material_admission=('CWE-20', ()))
    outcome.claim_refutations = (absent, declared) if not reverse else (declared, absent)
    outcome.hypotheses = []
    assert not claims_refuted(outcome, [outcome.hypothesis], source_identity=identity)


_RECEIPT_PROFILES = [tuple(name for index, name in enumerate(('legacy', 'absent', 'local', 'caller'))
                           if mask & (1 << index)) for mask in range(1, 16)]


@pytest.mark.parametrize('active', ['absent', 'local', 'caller'])
@pytest.mark.parametrize('profile', _RECEIPT_PROFILES)
def test_receipt_history_cannot_erase_known_material_by_arrival_order(tmp_path, active, profile):
    from dataclasses import replace

    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ClaimRefutation, ProbeOutcome, claims_refuted

    outcome, _, config = case(tmp_path)
    local, caller = deepcopy(outcome.hypotheses)
    identity = capture_source_identity(config.target_path, outcome.file)
    legacy = ClaimRefutation(outcome.file, outcome.function, outcome.line, outcome.hypothesis,
        (ProbeOutcome('semgrep', 'refuted', 'fixture-negative'),), identity)
    contexts = {'legacy': None, 'absent': ('CWE-20', ())}
    for name, declaration in [('local', local), ('caller', caller)]:
        outcome.hypotheses = [declaration]
        contexts[name] = orch._claim_material_admission(outcome, outcome.hypothesis)
    outcome.hypotheses = [] if active == 'absent' else [local if active == 'local' else caller]
    receipts = [replace(legacy, material_admission=contexts[name]) for name in profile]
    # A known statement must match; absence/legacy cannot stand in for it.
    # With no known statement history, retain the existing absence/legacy policy.
    if 'local' in profile or 'caller' in profile:
        expected = active in ('local', 'caller') and active in profile
    elif 'absent' in profile:
        expected = active == 'absent'
    else:
        expected = True
    for ordering in (receipts, list(reversed(receipts))):
        outcome.claim_refutations = tuple(ordering)
        assert claims_refuted(outcome, [outcome.hypothesis], source_identity=identity) is expected


@pytest.mark.parametrize('foreign', ['file', 'hypothesis', 'source'])
def test_foreign_context_does_not_shadow_an_independent_legacy_negative(tmp_path, foreign):
    from dataclasses import replace

    from core.audit.refutation_source import SourceIdentity, capture_source_identity
    from core.audit.verification_results import ClaimRefutation, ProbeOutcome, claims_refuted

    outcome, _, config = case(tmp_path)
    outcome.hypotheses = outcome.hypotheses[:1]
    identity = capture_source_identity(config.target_path, outcome.file)
    admission = orch._claim_material_admission(outcome, outcome.hypothesis)
    legacy = ClaimRefutation(outcome.file, outcome.function, outcome.line, outcome.hypothesis,
        (ProbeOutcome('semgrep', 'refuted', 'fixture-negative'),), identity)
    change = {'file': 'other.c'} if foreign == 'file' else (
        {'hypothesis': 'other concern'} if foreign == 'hypothesis' else
        {'source_identity': SourceIdentity('b' * 64, (1, 2, 3))})
    unrelated = replace(legacy, material_admission=admission, **change)
    outcome.hypotheses = []
    outcome.claim_refutations = (unrelated, legacy)
    assert claims_refuted(outcome, [outcome.hypothesis], source_identity=identity)
