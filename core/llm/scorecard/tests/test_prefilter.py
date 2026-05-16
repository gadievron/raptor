"""Tests for the consumer-facing prefilter helpers
(:mod:`core.llm.scorecard.prefilter`).

These verify the small-but-load-bearing glue every consumer uses:
``prefilter_decision`` and ``record_prefilter_outcome``. The
substrate's ``ModelScorecard`` is exercised separately.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.llm.scorecard import (
    EventType,
    ModelScorecard,
    Policy,
    prefilter_decision,
    record_prefilter_outcome,
)
from core.llm.scorecard.scorecard import _wilson_upper_bound


# ---------------------------------------------------------------------------
# prefilter_decision
# ---------------------------------------------------------------------------


def test_cheap_did_not_claim_fp_never_short_circuits(tmp_path):
    """``cheap_says_fp=False`` → fall through, regardless of how
    trustworthy the cell is. Without this rule, a cheap model that
    said 'needs analysis' would somehow trigger short-circuit just
    because the cell is trusted in general — which would silently
    skip the analysis the cheap model explicitly asked for."""
    sc = ModelScorecard(tmp_path / "sc.json")
    # Build a cell with strong trust track record.
    for _ in range(200):
        sc.record_event(
            "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    decision = prefilter_decision(
        sc, decision_class="x:y", model="m", cheap_says_fp=False,
    )
    assert decision.short_circuit is False


def test_cheap_says_fp_with_trusted_cell_short_circuits(tmp_path):
    sc = ModelScorecard(tmp_path / "sc.json")
    for _ in range(200):
        sc.record_event(
            "x:y", "m", EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    decision = prefilter_decision(
        sc, decision_class="x:y", model="m", cheap_says_fp=True,
    )
    assert decision.short_circuit is True
    assert decision.policy == Policy.SHORT_CIRCUIT


def test_cheap_says_fp_in_learning_falls_through(tmp_path):
    """In learning mode we always run full analysis even when cheap
    claims FP — the goal is to accumulate ground-truth comparison
    data."""
    sc = ModelScorecard(tmp_path / "sc.json")
    decision = prefilter_decision(
        sc, decision_class="x:y", model="m", cheap_says_fp=True,
    )
    assert decision.short_circuit is False
    assert decision.policy == Policy.LEARNING


def test_no_scorecard_falls_through(tmp_path):
    """When the operator opted out (``LLMConfig.scorecard_enabled=False``)
    the scorecard is None and we never short-circuit."""
    decision = prefilter_decision(
        None, decision_class="x:y", model="m", cheap_says_fp=True,
    )
    assert decision.short_circuit is False


# ---------------------------------------------------------------------------
# record_prefilter_outcome
# ---------------------------------------------------------------------------


def test_records_correct_when_cheap_and_full_agree(tmp_path):
    sc = ModelScorecard(tmp_path / "sc.json")
    record_prefilter_outcome(
        sc, decision_class="x:y", model="m",
        cheap_says_fp=True, full_says_fp=True,
        cheap_reasoning="not exploitable",
        full_reasoning="agree, not exploitable",
    )
    stat = sc.get_stat("x:y", "m")
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].correct == 1
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].incorrect == 0


def test_records_incorrect_with_sample_when_cheap_was_wrong(tmp_path):
    """When cheap said FP but full said TP, the cell records an
    incorrect outcome AND the disagreement sample for the operator
    to read later."""
    sc = ModelScorecard(tmp_path / "sc.json")
    record_prefilter_outcome(
        sc, decision_class="x:y", model="m",
        cheap_says_fp=True, full_says_fp=False,
        cheap_reasoning="cheap thought it was hardcoded",
        full_reasoning="full found user-tainted source via helper",
    )
    stat = sc.get_stat("x:y", "m")
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].incorrect == 1
    assert stat.events[EventType.CHEAP_SHORT_CIRCUIT].correct == 0
    assert len(stat.disagreement_samples) == 1
    assert "hardcoded" in stat.disagreement_samples[0]["this_reasoning"]
    assert "user-tainted" in stat.disagreement_samples[0]["other_reasoning"]


def test_no_record_when_cheap_did_not_claim_fp(tmp_path):
    """Records only when cheap claimed FP — those are the only events
    that feed the short-circuit gate. A cheap "needs_analysis" verdict
    paired with a full TP/FP carries no signal for the gate."""
    sc = ModelScorecard(tmp_path / "sc.json")
    record_prefilter_outcome(
        sc, decision_class="x:y", model="m",
        cheap_says_fp=False, full_says_fp=True,
        cheap_reasoning="needs analysis",
    )
    record_prefilter_outcome(
        sc, decision_class="x:y", model="m",
        cheap_says_fp=False, full_says_fp=False,
        cheap_reasoning="needs analysis",
    )
    assert sc.get_stat("x:y", "m") is None


def test_no_record_when_scorecard_is_none(tmp_path):
    """Operator opted out — record_prefilter_outcome is a no-op."""
    record_prefilter_outcome(
        None, decision_class="x:y", model="m",
        cheap_says_fp=True, full_says_fp=False,
    )
    # Just shouldn't raise.


def test_reasoning_text_is_truncated(tmp_path):
    """Long reasoning is capped at 500 chars to bound on-disk
    storage and avoid large code snippets ending up persisted."""
    sc = ModelScorecard(tmp_path / "sc.json")
    long_text = "X" * 5000
    record_prefilter_outcome(
        sc, decision_class="x:y", model="m",
        cheap_says_fp=True, full_says_fp=False,
        cheap_reasoning=long_text,
        full_reasoning=long_text,
    )
    stat = sc.get_stat("x:y", "m")
    assert len(stat.disagreement_samples[0]["this_reasoning"]) == 500
    assert len(stat.disagreement_samples[0]["other_reasoning"]) == 500
