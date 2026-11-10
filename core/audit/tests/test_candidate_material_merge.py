"""Unverified study candidates retain their own premises and confidence."""

from copy import deepcopy

from core.audit import orchestrator as orch


def outcome(primary, hypotheses):
    return orch.ReviewOutcome(
        file='source.c', function='f', line=1, status='suspicious', body='review',
        hypothesis=primary, hypotheses=deepcopy(hypotheses),
        review_result={'hypothesis': primary, 'cwe': 'CWE-20'},
    )


def test_merge_keeps_same_label_with_a_different_assumption():
    first = {'mechanism': 'range interpretation', 'confidence': 'medium',
             'counter_scope': 'local', 'assumed_property': 'local declaration', 'cwe': 'CWE-20'}
    second = {**first, 'counter_scope': 'cross_function',
              'assumed_property': 'caller declaration', 'confidence': 'high'}
    prior = outcome(first['mechanism'], [first])
    fresh = outcome(second['mechanism'], [second])
    merged = orch._merge_unverified_study_candidates(prior, fresh)
    assert merged is not None
    assert [h['assumed_property'] for h in merged.hypotheses] == [
        'local declaration', 'caller declaration',
    ]
    assert [h['confidence'] for h in merged.hypotheses] == ['medium', 'high']
    assert merged.hypothesis == prior.hypothesis
    assert prior.hypotheses == [first] and fresh.hypotheses == [second]
    assert not merged.claim_refutations and not merged.evidence_tool


def test_secondary_confidence_cannot_come_from_a_different_assumption():
    prior = outcome('prior concern', [])
    selected = {'mechanism': 'secondary concern', 'confidence': 'high',
                'counter_scope': 'local', 'assumed_property': 'local declaration'}
    excluded = {**selected, 'confidence': 'low', 'assumed_property': 'different declaration'}
    fresh = outcome('fresh primary', [selected, excluded])
    merged = orch._merge_unverified_study_candidates(prior, fresh)
    assert merged is not None
    secondary = [h for h in merged.hypotheses if h['mechanism'] == selected['mechanism']]
    assert len(secondary) == 1
    assert secondary[0]['assumed_property'] == selected['assumed_property']
    assert secondary[0]['confidence'] == 'high'


def test_equivalent_material_does_not_create_a_new_candidate():
    hypothesis = {'mechanism': 'range interpretation', 'confidence': 'medium',
                  'counter_scope': 'local', 'assumed_property': 'local declaration'}
    prior = outcome(hypothesis['mechanism'], [hypothesis])
    fresh = outcome(hypothesis['mechanism'], [{**hypothesis, 'confidence': 'high', 'cwe': 'CWE-20'}])
    assert orch._merge_unverified_study_candidates(prior, fresh) is None


def test_malformed_material_is_not_silently_removed_to_admit_a_candidate():
    prior = outcome('prior concern', [])
    fresh = outcome('fresh concern', [{'mechanism': 'fresh concern', 'confidence': 'high',
                                      'assumed_property': {'unknown': True}}])
    assert orch._merge_unverified_study_candidates(prior, fresh) is None
