"""Phase 4 tests for ``core.llm.scorecard.consensus.record_consensus_outcomes``.

When ``results_by_id[fid]`` carries a ``calibrated_aggregation`` block
with ``aggregation_method == "dawid_skene"``, the producer routes
updates through :meth:`ModelScorecard.record_event_soft` against the
``MULTI_MODEL_CONSENSUS_CALIBRATED`` event slot, using soft-label
credits derived from the posterior.

Otherwise the legacy majority-derived path (recording binary
correct/incorrect against ``MULTI_MODEL_CONSENSUS``) is preserved
exactly. The two paths coexist; existing test_consensus.py exercises
the legacy path.

The regression test that motivates Phase 4 (the "right dissenter" case)
lives here.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.llm.scorecard.consensus import record_consensus_outcomes
from core.llm.scorecard.scorecard import EventType, ModelScorecard


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scorecard(tmp_path: Path) -> ModelScorecard:
    return ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)


def _disputed_correlation(verdicts_by_model: dict, fid: str = "F1") -> dict:
    """Build a correlation with one disputed finding.

    ``verdicts_by_model`` is the {model: is_exploitable bool} dict
    the orchestrator's agreement_matrix produces for one finding.
    """
    return {
        "agreement_matrix": {
            fid: {m: {"is_exploitable": v} for m, v in verdicts_by_model.items()},
        },
        "confidence_signals": {fid: "disputed"},
    }


def _finding_with_posterior(
    fid: str, rule_id: str, posterior: float,
    *, method: str = "dawid_skene", is_exploitable: bool = True,
) -> dict:
    """Synthesize what the orchestrator would attach at line ~830."""
    return {
        "finding_id": fid,
        "rule_id": rule_id,
        "is_exploitable": is_exploitable,
        "calibrated_aggregation": {
            "posterior_true_positive": posterior,
            "credible_interval": [0.0, 1.0],
            "n_models": 3,
            "decision_class": f"agentic:{rule_id}",
            "aggregation_method": method,
            "aggregation_fallback_reason": None,
            "converged": True,
            "model_reliabilities": [],
        },
    }


def _calibrated_counts(sc: ModelScorecard, dc: str, model: str):
    """Read raw float counts from the calibrated event bucket. The
    public ``get_stat`` rounds for display; for credit accounting we
    want the underlying float values."""
    with sc._with_lock(write=False) as data:
        cell = data.get("models", {}).get(model, {}).get(dc, {})
        buckets = cell.get("events", {}).get(
            EventType.MULTI_MODEL_CONSENSUS_CALIBRATED, {},
        )
    correct = 0.0
    incorrect = 0.0
    for v in buckets.values():
        correct += float(v.get("correct", 0))
        incorrect += float(v.get("incorrect", 0))
    return correct, incorrect


# ---------------------------------------------------------------------------
# Regression: the "right dissenter" case
# ---------------------------------------------------------------------------


class TestRightDissenterRegression:
    """The structural motivation for Phase 4. Two unreliable models
    vote True; one reliable dissenter votes False. The calibrated
    posterior is near 0 (truly not exploitable). The legacy code
    would grade the dissenter as ``incorrect`` because it disagreed
    with majority. The calibrated path gives the dissenter the
    overwhelming majority of the ``correct`` credit instead."""

    def test_legacy_grades_dissenter_incorrect(self, scorecard):
        """Pin the bug the Phase 4 fix exists to remove."""
        correlation = _disputed_correlation({
            "majority1": True, "majority2": True, "dissenter": False,
        })
        # No calibrated_aggregation → legacy path runs
        results_by_id = {"F1": {"rule_id": "rule-a"}}
        record_consensus_outcomes(
            scorecard, correlation=correlation, results_by_id=results_by_id,
        )
        # Legacy: majority got "correct" (1), dissenter got "incorrect" (1).
        dc = "agentic:rule-a"
        s = scorecard.get_stat(dc, "dissenter")
        assert s is not None
        assert s.events[EventType.MULTI_MODEL_CONSENSUS].correct == 0
        assert s.events[EventType.MULTI_MODEL_CONSENSUS].incorrect == 1

    def test_calibrated_grades_dissenter_correct(self, scorecard):
        """With a near-zero posterior, the dissenter (who voted False)
        gets the overwhelming share of correct credit; the majority
        models (who voted True) get the overwhelming share of incorrect
        credit. This is the structural fix."""
        correlation = _disputed_correlation({
            "majority1": True, "majority2": True, "dissenter": False,
        })
        results_by_id = {
            "F1": _finding_with_posterior(
                "F1", "rule-a", posterior=0.05,  # near 0 → finding NOT exploitable
            ),
        }
        record_consensus_outcomes(
            scorecard, correlation=correlation, results_by_id=results_by_id,
        )
        dc = "agentic:rule-a"
        # Dissenter (voted False, truth ≈ False) → big correct credit.
        dc_correct, dc_incorrect = _calibrated_counts(scorecard, dc, "dissenter")
        assert dc_correct == pytest.approx(0.95, abs=1e-9)
        assert dc_incorrect == pytest.approx(0.05, abs=1e-9)
        # Majority (voted True, truth ≈ False) → big incorrect credit.
        for m in ("majority1", "majority2"):
            m_correct, m_incorrect = _calibrated_counts(scorecard, dc, m)
            assert m_correct == pytest.approx(0.05, abs=1e-9)
            assert m_incorrect == pytest.approx(0.95, abs=1e-9)


# ---------------------------------------------------------------------------
# Soft-credit invariants
# ---------------------------------------------------------------------------


class TestSoftCreditMath:
    def test_credits_sum_to_one_per_model(self, scorecard):
        """The soft-label fractional update is normalized: every
        (model, finding) contribution sums to 1.0 across correct +
        incorrect. No EM-side mass is created or destroyed.

        Uses a 3-model panel because the existing consensus loop
        skips 1-vs-1 ties (no clear majority); the calibrated path
        is invoked from inside the same loop.
        """
        correlation = _disputed_correlation({
            "m1": True, "m2": True, "m3": False,
        })
        results_by_id = {
            "F1": _finding_with_posterior("F1", "rule-a", posterior=0.7),
        }
        record_consensus_outcomes(
            scorecard, correlation=correlation, results_by_id=results_by_id,
        )
        dc = "agentic:rule-a"
        for m in ("m1", "m2", "m3"):
            c, i = _calibrated_counts(scorecard, dc, m)
            assert c + i == pytest.approx(1.0, abs=1e-9)

    @pytest.mark.parametrize("posterior", [0.05, 0.3, 0.5, 0.7, 0.95])
    def test_credit_magnitude_matches_posterior(self, scorecard, posterior):
        """A model that voted True should receive ``posterior`` units
        of correct credit and ``1 - posterior`` of incorrect."""
        correlation = _disputed_correlation({
            "m_true": True, "m_false": False, "m_tiebreak": True,
        })
        results_by_id = {
            "F1": _finding_with_posterior("F1", "rule-a", posterior=posterior),
        }
        record_consensus_outcomes(
            scorecard, correlation=correlation, results_by_id=results_by_id,
        )
        dc = "agentic:rule-a"
        c_true, i_true = _calibrated_counts(scorecard, dc, "m_true")
        assert c_true == pytest.approx(posterior, abs=1e-9)
        assert i_true == pytest.approx(1.0 - posterior, abs=1e-9)
        c_false, i_false = _calibrated_counts(scorecard, dc, "m_false")
        assert c_false == pytest.approx(1.0 - posterior, abs=1e-9)
        assert i_false == pytest.approx(posterior, abs=1e-9)


# ---------------------------------------------------------------------------
# Routing — which path does which finding take
# ---------------------------------------------------------------------------


class TestRouting:
    def test_vote_fallback_method_uses_legacy_path(self, scorecard):
        """When ``aggregation_method == "vote"`` (i.e. calibrated
        aggregation fell back to vote because the panel was too
        small), the consensus producer must use the legacy slot —
        the calibrated bucket gets no update."""
        correlation = _disputed_correlation({
            "m1": True, "m2": False, "m3": False,
        })
        results_by_id = {
            "F1": _finding_with_posterior(
                "F1", "rule-a", posterior=0.5, method="vote",
            ),
        }
        record_consensus_outcomes(
            scorecard, correlation=correlation, results_by_id=results_by_id,
        )
        dc = "agentic:rule-a"
        # Legacy slot populated
        s = scorecard.get_stat(dc, "m1")
        assert s.events[EventType.MULTI_MODEL_CONSENSUS].total() == 1
        # Calibrated slot empty
        c, i = _calibrated_counts(scorecard, dc, "m1")
        assert c == 0.0 and i == 0.0

    def test_missing_calibrated_aggregation_uses_legacy_path(self, scorecard):
        correlation = _disputed_correlation({
            "m1": True, "m2": False, "m3": False,
        })
        results_by_id = {"F1": {"rule_id": "rule-a"}}
        record_consensus_outcomes(
            scorecard, correlation=correlation, results_by_id=results_by_id,
        )
        dc = "agentic:rule-a"
        s = scorecard.get_stat(dc, "m1")
        assert s.events[EventType.MULTI_MODEL_CONSENSUS].total() == 1
        c, i = _calibrated_counts(scorecard, dc, "m1")
        assert c == 0.0 and i == 0.0

    def test_mixed_findings_route_per_finding(self, scorecard):
        """A run with some calibrated and some vote-fallback findings
        in the same correlation should route each to its own slot."""
        correlation = {
            "agreement_matrix": {
                "F1": {
                    "m1": {"is_exploitable": True},
                    "m2": {"is_exploitable": False},
                    "m3": {"is_exploitable": False},
                },
                "F2": {
                    "m1": {"is_exploitable": True},
                    "m2": {"is_exploitable": False},
                    "m3": {"is_exploitable": False},
                },
            },
            "confidence_signals": {"F1": "disputed", "F2": "disputed"},
        }
        results_by_id = {
            "F1": _finding_with_posterior(
                "F1", "rule-a", posterior=0.5, method="vote",
            ),
            "F2": _finding_with_posterior(
                "F2", "rule-b", posterior=0.9, method="dawid_skene",
            ),
        }
        record_consensus_outcomes(
            scorecard, correlation=correlation, results_by_id=results_by_id,
        )
        # F1 → legacy slot on rule-a; F2 → calibrated slot on rule-b
        s_a = scorecard.get_stat("agentic:rule-a", "m1")
        assert s_a.events[EventType.MULTI_MODEL_CONSENSUS].total() >= 1
        c, i = _calibrated_counts(scorecard, "agentic:rule-b", "m1")
        # m1 voted True; posterior 0.9 → correct=0.9, incorrect=0.1
        assert c == pytest.approx(0.9, abs=1e-9)
        assert i == pytest.approx(0.1, abs=1e-9)


# ---------------------------------------------------------------------------
# Coexistence with legacy data
# ---------------------------------------------------------------------------


class TestSchemaCompat:
    def test_int_and_float_buckets_coexist_in_one_cell(self, scorecard):
        """Phase 4 doesn't migrate legacy ``multi_model_consensus``
        counts. The cell can carry int counts in the legacy slot and
        float counts in the calibrated slot simultaneously."""
        # Push a legacy int update
        scorecard.record_event(
            decision_class="agentic:rule-a", model="m1",
            event_type=EventType.MULTI_MODEL_CONSENSUS, outcome="correct",
        )
        # Push a calibrated float update
        scorecard.record_event_soft(
            decision_class="agentic:rule-a", model="m1",
            event_type=EventType.MULTI_MODEL_CONSENSUS_CALIBRATED,
            correct=0.7, incorrect=0.3,
        )
        s = scorecard.get_stat("agentic:rule-a", "m1")
        # Legacy slot: int(1, 0)
        assert s.events[EventType.MULTI_MODEL_CONSENSUS].correct == 1
        assert s.events[EventType.MULTI_MODEL_CONSENSUS].incorrect == 0
        # Calibrated slot rounds to int for display; raw buckets retain floats
        c, i = _calibrated_counts(scorecard, "agentic:rule-a", "m1")
        assert c == pytest.approx(0.7, abs=1e-9)
        assert i == pytest.approx(0.3, abs=1e-9)

    def test_record_event_soft_accumulates(self, scorecard):
        for credit_correct, credit_incorrect in [(0.7, 0.3), (0.4, 0.6), (1.0, 0.0)]:
            scorecard.record_event_soft(
                decision_class="agentic:rule-a", model="m1",
                event_type=EventType.MULTI_MODEL_CONSENSUS_CALIBRATED,
                correct=credit_correct, incorrect=credit_incorrect,
            )
        c, i = _calibrated_counts(scorecard, "agentic:rule-a", "m1")
        assert c == pytest.approx(2.1, abs=1e-9)
        assert i == pytest.approx(0.9, abs=1e-9)

    def test_record_event_soft_rejects_negative_credits(self, scorecard):
        with pytest.raises(ValueError):
            scorecard.record_event_soft(
                decision_class="x", model="m1",
                event_type=EventType.MULTI_MODEL_CONSENSUS_CALIBRATED,
                correct=-0.1, incorrect=0.5,
            )

    def test_record_event_soft_rejects_unknown_event_type(self, scorecard):
        with pytest.raises(ValueError, match="unknown event_type"):
            scorecard.record_event_soft(
                decision_class="x", model="m1",
                event_type="not_a_real_event_type",
                correct=0.5, incorrect=0.5,
            )
