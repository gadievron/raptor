"""Tests for ``core.llm.scorecard.judge.record_judge_outcomes``.

Pins the producer's contract:
  * Multi-judge disputes record one event per (model, finding):
    primary's vote vs final, each judge's vote vs final.
  * Single-judge disputes skipped (no panel-majority truth signal).
  * Agreed findings skipped.
  * Decision class shape ``agentic:<rule_id>``.
  * Cheap-tier counters untouched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.llm.scorecard.judge import record_judge_outcomes
from core.llm.scorecard.scorecard import EventType, ModelScorecard


@pytest.fixture
def scorecard(tmp_path: Path) -> ModelScorecard:
    return ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)


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
        n = record_judge_outcomes(
            None,
            results_by_id={},
            primary_verdicts_before_judge={},
        )
        assert n == 0

    def test_empty_results(self, scorecard):
        n = record_judge_outcomes(
            scorecard,
            results_by_id={},
            primary_verdicts_before_judge={},
        )
        assert n == 0

    def test_skips_findings_without_judge_field(self, scorecard):
        results = {"f1": {"rule_id": "py/x", "is_exploitable": True}}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 0

    def test_skips_error_results(self, scorecard):
        results = {"f1": {"error": "timeout", "judge": "disputed"}}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Multi-judge disputes — events recorded
# ---------------------------------------------------------------------------


class TestMultiJudgeDispute:
    def test_panel_overrules_primary(self, scorecard):
        """Primary said exploitable; 2 judges said not. Final is
        not-exploitable. Primary → incorrect; judges → correct."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,                    # final
            "analysed_by": "claude-opus",
            "reasoning": "primary thought tainted",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": False,
                 "reasoning": "actually constant"},
                {"model": "gemini", "is_exploitable": False,
                 "reasoning": "validated input"},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},  # primary said True
        )
        assert n == 3
        dc = "agentic:py/sql-injection"
        assert _stat(scorecard, dc, "claude-opus", EventType.JUDGE_REVIEW) == (0, 1)
        assert _stat(scorecard, dc, "gpt-4",       EventType.JUDGE_REVIEW) == (1, 0)
        assert _stat(scorecard, dc, "gemini",      EventType.JUDGE_REVIEW) == (1, 0)

    def test_panel_kept_primary(self, scorecard):
        """Primary said exploitable; 1 judge dissented but the other
        agreed. With 3 voters (primary + 2 judges) and 2-vs-1
        in-favour, final stays exploitable. Primary → correct;
        agreeing judge → correct; dissenting judge → incorrect."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": True,                     # final
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-4",  "is_exploitable": True},
                {"model": "gemini", "is_exploitable": False,
                 "reasoning": "thought it was sanitised"},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 3
        dc = "agentic:py/sql-injection"
        assert _stat(scorecard, dc, "claude-opus", EventType.JUDGE_REVIEW) == (1, 0)
        assert _stat(scorecard, dc, "gpt-4",       EventType.JUDGE_REVIEW) == (1, 0)
        assert _stat(scorecard, dc, "gemini",      EventType.JUDGE_REVIEW) == (0, 1)

    def test_minority_reasoning_captured(self, scorecard):
        """Dissenter's reasoning attached to disagreement-samples log."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,
            "analysed_by": "claude-opus",
            "reasoning": "primary: clearly tainted via request.GET",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": False, "reasoning": "ok"},
                {"model": "gemini", "is_exploitable": False, "reasoning": "ok"},
            ],
        }}
        record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        s = scorecard.get_stat("agentic:py/sql-injection", "claude-opus")
        samples = [
            samp for samp in s.disagreement_samples
            if samp.get("event_type") == EventType.JUDGE_REVIEW
        ]
        assert len(samples) == 1
        assert "tainted via request.GET" in samples[0]["this_reasoning"]


# ---------------------------------------------------------------------------
# Single-judge disputes — INTENTIONALLY skipped
# ---------------------------------------------------------------------------


class TestSingleJudgeSkipped:
    def test_single_judge_dispute_records_nothing(self, scorecard):
        """``JudgeTask.finalize`` keeps primary's verdict when there's
        only one judge — there's no panel-majority truth signal and
        recording would arbitrarily flag one side. Skip cleanly."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": True,                     # primary kept
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": False,
                 "reasoning": "single-judge dissent"},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 0
        # No events for either model.
        assert scorecard.get_stat("agentic:py/sql-injection", "claude-opus") is None
        assert scorecard.get_stat("agentic:py/sql-injection", "gpt-4") is None


# ---------------------------------------------------------------------------
# Agreed cases — skipped (no useful signal)
# ---------------------------------------------------------------------------


class TestAgreedSkipped:
    def test_agreed_no_events(self, scorecard):
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "agreed",
            "is_exploitable": True,
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": True},
                {"model": "gemini", "is_exploitable": True},
            ],
        }}
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        assert n == 0


# ---------------------------------------------------------------------------
# Decision-class shape + isolation
# ---------------------------------------------------------------------------


class TestIsolationFromGate:
    def test_does_not_pollute_cheap_short_circuit(self, scorecard):
        # Pre-seed cheap-tier counter.
        for _ in range(20):
            scorecard.record_event(
                "agentic:py/sql-injection", "claude-opus",
                EventType.CHEAP_SHORT_CIRCUIT, "correct",
            )
        before = _stat(scorecard, "agentic:py/sql-injection", "claude-opus",
                       EventType.CHEAP_SHORT_CIRCUIT)

        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": False},
                {"model": "gemini", "is_exploitable": False},
            ],
        }}
        record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={"f1": True},
        )
        after = _stat(scorecard, "agentic:py/sql-injection", "claude-opus",
                      EventType.CHEAP_SHORT_CIRCUIT)
        assert before == after


class TestMissingSnapshot:
    def test_skips_when_primary_snapshot_missing(self, scorecard):
        """Defensive: if the caller didn't snapshot primary's verdict
        before judge ran, the producer can't know which way primary
        originally voted (JudgeTask overwrote it). Skip rather than
        mis-attribute."""
        results = {"f1": {
            "rule_id": "py/sql-injection",
            "judge": "disputed",
            "is_exploitable": False,
            "analysed_by": "claude-opus",
            "judge_analyses": [
                {"model": "gpt-4", "is_exploitable": False},
                {"model": "gemini", "is_exploitable": False},
            ],
        }}
        # Empty snapshot.
        n = record_judge_outcomes(
            scorecard,
            results_by_id=results,
            primary_verdicts_before_judge={},
        )
        assert n == 0
