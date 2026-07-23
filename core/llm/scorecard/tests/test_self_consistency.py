"""Tests for self-consistency scorecard producer."""

from __future__ import annotations

from pathlib import Path

from core.llm.scorecard.scorecard import EventType, ModelScorecard
from core.llm.scorecard.self_consistency import (
    record_self_consistency_outcomes,
)


def _make_result(finding_id, *, is_exploitable=True, retried=False,
                 rule_id="test-rule", model="gemini-2.5-pro",
                 reasoning="some reasoning"):
    r = {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "analysed_by": model,
        "resolved_model": model,
        "is_exploitable": is_exploitable,
        "reasoning": reasoning,
    }
    if retried:
        r["retried"] = True
    return r


class TestRecordSelfConsistencyOutcomes:
    def test_none_scorecard_returns_zero(self):
        assert record_self_consistency_outcomes(
            None, results_by_id={}, verdicts_pre_retry={},
        ) == 0

    def test_no_retried_findings(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result("F-001")}
        assert record_self_consistency_outcomes(
            sc, results_by_id=results, verdicts_pre_retry={"F-001": True},
        ) == 0

    def test_held_verdict_records_correct(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result("F-001", is_exploitable=True, retried=True)}
        pre = {"F-001": True}
        n = record_self_consistency_outcomes(
            sc, results_by_id=results, verdicts_pre_retry=pre,
        )
        assert n == 1
        cell = next(s for s in sc.get_stats() if s.model == "gemini-2.5-pro")
        ec = cell.events[EventType.SELF_CONSISTENCY]
        assert ec.correct == 1

    def test_flipped_verdict_records_incorrect(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result("F-001", is_exploitable=False, retried=True)}
        pre = {"F-001": True}
        n = record_self_consistency_outcomes(
            sc, results_by_id=results, verdicts_pre_retry=pre,
        )
        assert n == 1
        cell = next(s for s in sc.get_stats() if s.model == "gemini-2.5-pro")
        ec = cell.events[EventType.SELF_CONSISTENCY]
        assert ec.incorrect == 1

    def test_flipped_captures_sample(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        sc.retain_samples = True
        results = {"F-001": _make_result(
            "F-001", is_exploitable=False, retried=True,
            reasoning="On second look this is safe",
        )}
        pre = {"F-001": True}
        record_self_consistency_outcomes(
            sc, results_by_id=results, verdicts_pre_retry=pre,
        )
        cell = next(s for s in sc.get_stats() if s.model == "gemini-2.5-pro")
        assert len(cell.disagreement_samples) == 1
        assert cell.disagreement_samples[0]["pre_verdict"] == "positive"
        assert cell.disagreement_samples[0]["post_verdict"] == "negative"
        assert "On second look" in cell.disagreement_samples[0]["post_reasoning"]

    def test_skips_finding_not_in_pre_snapshot(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result("F-001", retried=True)}
        assert record_self_consistency_outcomes(
            sc, results_by_id=results, verdicts_pre_retry={},
        ) == 0

    def test_decision_class_format(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001", retried=True, rule_id="cpp/buffer-overflow",
        )}
        pre = {"F-001": True}
        record_self_consistency_outcomes(
            sc, results_by_id=results, verdicts_pre_retry=pre,
        )
        classes = {s.decision_class for s in sc.get_stats()}
        assert "agentic:cpp/buffer-overflow" in classes

    def test_skips_none_post_verdict(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        r = _make_result("F-001", retried=True)
        r["is_exploitable"] = None
        results = {"F-001": r}
        assert record_self_consistency_outcomes(
            sc, results_by_id=results, verdicts_pre_retry={"F-001": True},
        ) == 0

    def test_skips_empty_model(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        r = _make_result("F-001", retried=True, model="")
        results = {"F-001": r}
        assert record_self_consistency_outcomes(
            sc, results_by_id=results, verdicts_pre_retry={"F-001": True},
        ) == 0

    def test_multiple_mixed(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {
            "F-001": _make_result("F-001", is_exploitable=True, retried=True),
            "F-002": _make_result("F-002", is_exploitable=False, retried=True),
            "F-003": _make_result("F-003", is_exploitable=True),
        }
        pre = {"F-001": True, "F-002": True, "F-003": True}
        n = record_self_consistency_outcomes(
            sc, results_by_id=results, verdicts_pre_retry=pre,
        )
        assert n == 2
        cell = next(s for s in sc.get_stats() if s.model == "gemini-2.5-pro")
        ec = cell.events[EventType.SELF_CONSISTENCY]
        assert ec.correct == 1
        assert ec.incorrect == 1
