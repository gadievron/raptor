"""Mechanism-only receipts cannot settle distinct structured assumptions."""

from copy import deepcopy

from core.audit.orchestrator import ReviewOutcome
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome, claims_refuted


def fixture_outcome():
    identity = SourceIdentity('a' * 64, (1, 2, 3))
    variants = [
        {'mechanism': 'range interpretation', 'confidence': 'high',
         'counter_scope': 'local', 'assumed_property': 'local declaration'},
        {'mechanism': 'range interpretation', 'confidence': 'medium',
         'counter_scope': 'cross_function', 'assumed_property': 'caller declaration'},
    ]
    outcome = ReviewOutcome(
        file='source.c', function='f', line=1, status='suspicious', body='',
        hypothesis='range interpretation', hypotheses=deepcopy(variants),
        review_result={'hypothesis': 'range interpretation', 'cwe': 'CWE-20'},
    )
    receipt = ClaimRefutation('source.c', 'f', 1, 'range interpretation',
                              (ProbeOutcome('semgrep', 'refuted', 'fixture'),), identity)
    outcome.claim_refutations = (receipt,)
    return outcome, identity, variants


def test_one_label_receipt_cannot_refute_two_material_variants():
    outcome, identity, _ = fixture_outcome()
    assert not claims_refuted(outcome, ['range interpretation'], source_identity=identity)


def test_equivalent_material_duplicates_keep_existing_receipt_authority():
    outcome, identity, variants = fixture_outcome()
    outcome.hypotheses = [variants[0], {**variants[0], 'confidence': 'medium', 'is_primary': False}]
    assert claims_refuted(outcome, ['range interpretation'], source_identity=identity)


def test_conflicting_review_copy_cannot_hide_behind_attribute_precedence():
    outcome, identity, variants = fixture_outcome()
    outcome.hypotheses = [variants[0]]
    outcome.review_result['hypotheses'] = [variants[1]]
    assert not claims_refuted(outcome, ['range interpretation'], source_identity=identity)


def test_unrelated_material_does_not_block_an_independent_negative():
    outcome, identity, variants = fixture_outcome()
    outcome.hypotheses = [variants[0], {**variants[1], 'mechanism': 'another concern'}]
    assert claims_refuted(outcome, ['range interpretation'], source_identity=identity)
    assert not claims_refuted(outcome, ['another concern'], source_identity=identity)


def test_new_assessment_must_check_prior_material_before_using_a_receipt():
    prior, identity, _ = fixture_outcome()
    fresh = ReviewOutcome(file=prior.file, function=prior.function, line=prior.line,
                          status='clean', body='review', hypothesis='')
    fresh.claim_refutations = prior.claim_refutations
    assert claims_refuted(fresh, ['range interpretation'], source_identity=identity)
    assert not claims_refuted(fresh, ['range interpretation'], source_identity=identity, claim_outcome=prior)


def test_malformed_material_is_not_equivalent_to_missing_material():
    outcome, identity, variants = fixture_outcome()
    outcome.hypotheses = [variants[0], {**variants[0], 'assumed_property': {'unknown': True}}]
    assert not claims_refuted(outcome, ['range interpretation'], source_identity=identity)


def test_legacy_text_claim_and_source_scope_are_preserved():
    outcome, identity, _ = fixture_outcome()
    outcome.hypotheses = None
    assert claims_refuted(outcome, ['range interpretation'], source_identity=identity)
    assert not claims_refuted(outcome, ['range interpretation'], source_identity=None)
    assert not claims_refuted(outcome, ['range interpretation'], source_identity=SourceIdentity('b' * 64, (1, 2, 3)))


def test_conflicting_material_across_assessments_cannot_share_a_negative():
    prior, identity, variants = fixture_outcome()
    prior.hypotheses = [variants[0]]
    fresh = deepcopy(prior)
    fresh.hypotheses = [variants[1]]
    assert not claims_refuted(fresh, ['range interpretation'], source_identity=identity, claim_outcome=prior)
