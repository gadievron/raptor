"""Empirical binary absence is an observation, not a source proof."""
from core.analysis.reach_witness import (
    Reachability, Soundness, WitnessKind, verdict_from_classification,
)


def test_classifier_absence_cannot_earn_source_suppression_from_corpus_membership():
    verdict = verdict_from_classification("binary_oracle_absent")
    assert verdict.may_suppress(frozenset({WitnessKind.BINARY_ORACLE_ABSENT})) is False
    assert verdict.status is Reachability.UNCERTAIN
    assert verdict.witness.soundness is Soundness.HEURISTIC
    assert verdict.witness.kind is WitnessKind.BINARY_ORACLE_ABSENT
