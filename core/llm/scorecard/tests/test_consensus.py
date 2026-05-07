"""Tests for ``core.llm.scorecard.consensus.record_consensus_outcomes``.

Pins the producer's contract:
  * Disputed findings produce one event per (model, finding) pair
    — minority gets ``incorrect``, majority gets ``correct``.
  * Agreed findings produce no events (no useful signal).
  * Ties (1-vs-1, 2-vs-2) skipped — no clear majority.
  * Decision class shape: ``agentic:<rule_id>``.
  * Cheap-tier counters untouched (this producer feeds its own slot).
  * No-op on ``scorecard=None`` or empty correlation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.llm.scorecard.consensus import record_consensus_outcomes
from core.llm.scorecard.scorecard import EventType, ModelScorecard


@pytest.fixture
def scorecard(tmp_path: Path) -> ModelScorecard:
    return ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)


def _correlation(*, matrix, confidence):
    return {
        "agreement_matrix": matrix,
        "confidence_signals": confidence,
    }


def _stat(sc: ModelScorecard, dc: str, model: str, ev: str):
    s = sc.get_stat(dc, model)
    if s is None:
        return (0, 0)
    return s.events[ev].correct, s.events[ev].incorrect


# ---------------------------------------------------------------------------
# No-op paths
# ---------------------------------------------------------------------------


class TestNoOp:
    def test_none_scorecard(self):
        n = record_consensus_outcomes(
            None,
            correlation={"agreement_matrix": {}, "confidence_signals": {}},
            results_by_id={},
        )
        assert n == 0

    def test_empty_correlation(self, scorecard):
        n = record_consensus_outcomes(
            scorecard, correlation={}, results_by_id={},
        )
        assert n == 0

    def test_empty_matrix(self, scorecard):
        n = record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix={}, confidence={}),
            results_by_id={},
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Disputed findings → events recorded
# ---------------------------------------------------------------------------


class TestDisputedFindings:
    def test_2v1_minority_incorrect_majority_correct(self, scorecard):
        """3-model panel, 2 say exploitable, 1 dissents.
        Majority (2) → correct; minority (1) → incorrect."""
        matrix = {
            "f1": {
                "pro":   {"is_exploitable": True},
                "opus":  {"is_exploitable": True},
                "flash": {"is_exploitable": False},
            },
        }
        confidence = {"f1": "disputed"}
        results = {"f1": {"rule_id": "py/sql-injection", "reasoning": "..."}}

        n = record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
        )
        assert n == 3

        dc = "agentic:py/sql-injection"
        assert _stat(scorecard, dc, "pro",   EventType.MULTI_MODEL_CONSENSUS) == (1, 0)
        assert _stat(scorecard, dc, "opus",  EventType.MULTI_MODEL_CONSENSUS) == (1, 0)
        assert _stat(scorecard, dc, "flash", EventType.MULTI_MODEL_CONSENSUS) == (0, 1)

    def test_1v2_minority_incorrect_majority_correct(self, scorecard):
        """Symmetric case: 2 say not-exploitable, 1 dissents (says exploitable)."""
        matrix = {
            "f1": {
                "pro":   {"is_exploitable": False},
                "opus":  {"is_exploitable": False},
                "flash": {"is_exploitable": True},
            },
        }
        confidence = {"f1": "disputed"}
        results = {"f1": {"rule_id": "py/sql-injection"}}

        record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
        )
        dc = "agentic:py/sql-injection"
        assert _stat(scorecard, dc, "pro",   EventType.MULTI_MODEL_CONSENSUS) == (1, 0)
        assert _stat(scorecard, dc, "opus",  EventType.MULTI_MODEL_CONSENSUS) == (1, 0)
        assert _stat(scorecard, dc, "flash", EventType.MULTI_MODEL_CONSENSUS) == (0, 1)

    def test_minority_reasoning_captured_as_sample(self, scorecard):
        """Minority's own reasoning attached to the disagreement-
        samples log when ``per_finding_results`` is supplied."""
        matrix = {
            "f1": {
                "pro":   {"is_exploitable": True},
                "opus":  {"is_exploitable": True},
                "flash": {"is_exploitable": False},
            },
        }
        confidence = {"f1": "disputed"}
        results = {"f1": {"rule_id": "py/sql-injection"}}
        per_finding_results = {"f1": [
            {"analysed_by": "pro", "reasoning": "pro: clearly tainted"},
            {"analysed_by": "opus", "reasoning": "opus: tainted"},
            {"analysed_by": "flash", "reasoning": "flash: input is hardcoded"},
        ]}

        record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
            per_finding_results=per_finding_results,
        )
        s = scorecard.get_stat("agentic:py/sql-injection", "flash")
        flash_samples = [
            samp for samp in s.disagreement_samples
            if samp.get("event_type") == EventType.MULTI_MODEL_CONSENSUS
        ]
        assert len(flash_samples) == 1
        assert "input is hardcoded" in flash_samples[0]["this_reasoning"]
        assert "majority" in flash_samples[0]["other_reasoning"]

    def test_minority_no_sample_when_per_finding_results_missing(self, scorecard):
        """Adversarial: caller didn't supply per_finding_results.
        Producer skips the sample rather than mis-attribute the
        primary's reasoning to the dissenter. Counters still bump."""
        matrix = {
            "f1": {
                "pro":   {"is_exploitable": True},
                "opus":  {"is_exploitable": True},
                "flash": {"is_exploitable": False},
            },
        }
        confidence = {"f1": "disputed"}
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "reasoning": "primary's reasoning — must NOT be attributed to flash",
        }}
        record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
            per_finding_results=None,
        )
        s = scorecard.get_stat("agentic:py/sql-injection", "flash")
        # Counter bumped (the dissent is recorded).
        assert s.events[EventType.MULTI_MODEL_CONSENSUS].incorrect == 1
        # But no sample — would have mis-attributed the primary's
        # text to flash, which is misleading.
        flash_samples = [
            samp for samp in s.disagreement_samples
            if samp.get("event_type") == EventType.MULTI_MODEL_CONSENSUS
        ]
        assert flash_samples == []


# ---------------------------------------------------------------------------
# Skip paths — no events when signal isn't useful
# ---------------------------------------------------------------------------


class TestSkipPaths:
    def test_agreed_findings_skipped(self, scorecard):
        """All models agreed → no event recorded. Avoids bumping
        every model's counter on every agreed finding (noise)."""
        matrix = {
            "f1": {
                "pro":   {"is_exploitable": True},
                "opus":  {"is_exploitable": True},
                "flash": {"is_exploitable": True},
            },
        }
        confidence = {"f1": "high"}
        results = {"f1": {"rule_id": "py/x"}}

        n = record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
        )
        assert n == 0

    def test_tie_1v1_skipped(self, scorecard):
        """1-vs-1 split in a 2-model panel → no clear majority. Skip
        rather than arbitrarily declare one model wrong."""
        matrix = {
            "f1": {
                "pro":   {"is_exploitable": True},
                "flash": {"is_exploitable": False},
            },
        }
        # Note: with 1==1 the existing correlation labels this
        # "disputed" too; we skip downstream of that signal.
        confidence = {"f1": "disputed"}
        results = {"f1": {"rule_id": "py/x"}}

        n = record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
        )
        assert n == 0

    def test_tie_2v2_skipped(self, scorecard):
        matrix = {
            "f1": {
                "a": {"is_exploitable": True},
                "b": {"is_exploitable": True},
                "c": {"is_exploitable": False},
                "d": {"is_exploitable": False},
            },
        }
        confidence = {"f1": "disputed"}
        results = {"f1": {"rule_id": "py/x"}}

        n = record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
        )
        assert n == 0

    def test_missing_verdict_excludes_model(self, scorecard):
        """A model with ``is_exploitable=None`` (handler error / schema
        failure) doesn't have a vote — exclude it from the majority
        calculation rather than counting it as either."""
        matrix = {
            "f1": {
                "pro":   {"is_exploitable": True},
                "opus":  {"is_exploitable": True},
                "flash": {"is_exploitable": False},
                "broken": {"is_exploitable": None},  # model errored
            },
        }
        confidence = {"f1": "disputed"}
        results = {"f1": {"rule_id": "py/x"}}

        n = record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
        )
        # 3 events: pro+opus correct, flash incorrect. broken: no event.
        assert n == 3
        assert scorecard.get_stat("agentic:py/x", "broken") is None

    def test_under_two_voters_skipped(self, scorecard):
        """If only one model has a verdict (others all errored),
        there's nothing to compare against — skip."""
        matrix = {
            "f1": {
                "pro":   {"is_exploitable": True},
                "broken1": {"is_exploitable": None},
                "broken2": {"is_exploitable": None},
            },
        }
        confidence = {"f1": "disputed"}
        results = {"f1": {"rule_id": "py/x"}}

        n = record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Decision-class shape + isolation from gate
# ---------------------------------------------------------------------------


class TestDecisionClass:
    def test_decision_class_uses_agentic_prefix(self, scorecard):
        matrix = {
            "f1": {
                "pro":   {"is_exploitable": True},
                "opus":  {"is_exploitable": True},
                "flash": {"is_exploitable": False},
            },
        }
        confidence = {"f1": "disputed"}
        results = {"f1": {"rule_id": "java/path-traversal"}}

        record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
        )
        # Cell exists under agentic:java/path-traversal, NOT bare
        # rule_id and NOT codeql:.
        all_classes = {s.decision_class for s in scorecard.get_stats()}
        assert "agentic:java/path-traversal" in all_classes
        assert "java/path-traversal" not in all_classes
        assert "codeql:java/path-traversal" not in all_classes

    def test_unknown_rule_id_substituted(self, scorecard):
        matrix = {
            "f1": {
                "pro":   {"is_exploitable": True},
                "opus":  {"is_exploitable": True},
                "flash": {"is_exploitable": False},
            },
        }
        confidence = {"f1": "disputed"}
        # Result missing rule_id — producer falls back to "unknown"
        # rather than crashing.
        results = {"f1": {}}
        record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
        )
        all_classes = {s.decision_class for s in scorecard.get_stats()}
        assert "agentic:unknown" in all_classes


class TestIsolationFromGate:
    def test_does_not_pollute_cheap_short_circuit(self, scorecard):
        """The auto-policy gate's Wilson math runs over
        CHEAP_SHORT_CIRCUIT only. Recording MULTI_MODEL_CONSENSUS
        events MUST NOT bump that counter — otherwise consensus
        signals would silently shift the prefilter gate's behaviour."""
        # Pre-seed cheap-tier with confident-trust state.
        for _ in range(20):
            scorecard.record_event(
                "agentic:py/x", "flash",
                EventType.CHEAP_SHORT_CIRCUIT, "correct",
            )
        before = _stat(scorecard, "agentic:py/x", "flash",
                       EventType.CHEAP_SHORT_CIRCUIT)

        matrix = {"f1": {
            "pro":   {"is_exploitable": True},
            "opus":  {"is_exploitable": True},
            "flash": {"is_exploitable": False},
        }}
        confidence = {"f1": "disputed"}
        results = {"f1": {"rule_id": "py/x"}}
        record_consensus_outcomes(
            scorecard,
            correlation=_correlation(matrix=matrix, confidence=confidence),
            results_by_id=results,
        )
        after = _stat(scorecard, "agentic:py/x", "flash",
                      EventType.CHEAP_SHORT_CIRCUIT)
        assert before == after  # cheap-tier counter unchanged
