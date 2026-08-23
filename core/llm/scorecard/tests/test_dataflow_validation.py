"""Tests for dataflow validation scorecard producer."""

from __future__ import annotations

from pathlib import Path

from core.llm.scorecard.dataflow_validation import (
    record_dataflow_validation_outcomes,
)
from core.llm.scorecard.scorecard import EventType, ModelScorecard


def _make_result(finding_id, *, dv=None, rule_id="test-rule",
                 model="gemini-2.5-pro"):
    r = {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "analysed_by": model,
        "resolved_model": model,
        "is_exploitable": True,
        "reasoning": "some reasoning",
    }
    if dv is not None:
        r["dataflow_validation"] = dv
    return r


class TestRecordDataflowValidationOutcomes:
    def test_none_scorecard_returns_zero(self):
        assert record_dataflow_validation_outcomes(
            None, results_by_id={},
        ) == 0

    def test_no_dataflow_findings(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result("F-001")}
        assert record_dataflow_validation_outcomes(
            sc, results_by_id=results,
        ) == 0

    def test_confirmed_records_correct(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result("F-001", dv={
            "verdict": "confirmed",
            "reasoning": "path exists",
            "method": "codeql-iris",
        })}
        n = record_dataflow_validation_outcomes(sc, results_by_id=results)
        assert n == 1
        cell = next(s for s in sc.get_stats() if s.model == "gemini-2.5-pro")
        ec = cell.events[EventType.DATAFLOW_VALIDATION]
        assert ec.correct == 1

    def test_refuted_records_incorrect(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result("F-001", dv={
            "verdict": "refuted",
            "reasoning": "no path from source to sink",
            "method": "structural-treesitter",
        })}
        n = record_dataflow_validation_outcomes(sc, results_by_id=results)
        assert n == 1
        cell = next(s for s in sc.get_stats() if s.model == "gemini-2.5-pro")
        ec = cell.events[EventType.DATAFLOW_VALIDATION]
        assert ec.incorrect == 1

    def test_inconclusive_skipped(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result("F-001", dv={
            "verdict": "inconclusive",
            "reasoning": "insufficient evidence",
            "method": "codeql-iris",
        })}
        assert record_dataflow_validation_outcomes(
            sc, results_by_id=results,
        ) == 0

    def test_refuted_captures_sample(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        sc.retain_samples = True
        results = {"F-001": _make_result("F-001", dv={
            "verdict": "refuted",
            "reasoning": "sanitiser at call site prevents injection",
            "method": "codeql-iris",
        })}
        record_dataflow_validation_outcomes(sc, results_by_id=results)
        cell = next(s for s in sc.get_stats() if s.model == "gemini-2.5-pro")
        assert len(cell.disagreement_samples) == 1
        assert cell.disagreement_samples[0]["method"] == "codeql-iris"
        assert "sanitiser" in cell.disagreement_samples[0]["reasoning"]

    def test_decision_class_format(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001", rule_id="py/command-injection",
            dv={"verdict": "confirmed", "reasoning": "ok", "method": "codeql-iris"},
        )}
        record_dataflow_validation_outcomes(sc, results_by_id=results)
        classes = {s.decision_class for s in sc.get_stats()}
        assert "agentic:py/command-injection" in classes

    def test_multiple_mixed(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {
            "F-001": _make_result("F-001", dv={
                "verdict": "confirmed", "reasoning": "ok", "method": "codeql-iris",
            }),
            "F-002": _make_result("F-002", dv={
                "verdict": "refuted", "reasoning": "no path", "method": "codeql-iris",
            }),
            "F-003": _make_result("F-003", dv={
                "verdict": "inconclusive", "reasoning": "meh", "method": "codeql-iris",
            }),
            "F-004": _make_result("F-004"),
        }
        n = record_dataflow_validation_outcomes(sc, results_by_id=results)
        assert n == 2
        cell = next(s for s in sc.get_stats() if s.model == "gemini-2.5-pro")
        ec = cell.events[EventType.DATAFLOW_VALIDATION]
        assert ec.correct == 1
        assert ec.incorrect == 1
