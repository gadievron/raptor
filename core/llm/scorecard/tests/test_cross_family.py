"""Tests for cross-family check scorecard producer."""

from __future__ import annotations

from pathlib import Path

from core.llm.scorecard.cross_family import record_cross_family_outcomes
from core.llm.scorecard.scorecard import EventType, ModelScorecard


def _make_result(finding_id, *, rule_id="test-rule", model="gemini-2.5-pro",
                 cf_check=None, cf_agreed=False, cf_disputed=False):
    r = {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "analysed_by": model,
        "resolved_model": model,
        "is_exploitable": True,
        "reasoning": "some reasoning",
    }
    if cf_check is not None:
        r["cross_family_check"] = cf_check
    if cf_agreed:
        r["cross_family_agreed"] = True
    if cf_disputed:
        r["cross_family_disputed"] = True
    return r


class TestRecordCrossFamilyOutcomes:
    def test_none_scorecard_returns_zero(self):
        assert record_cross_family_outcomes(None, results_by_id={}) == 0

    def test_no_cross_family_findings(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result("F-001")}
        assert record_cross_family_outcomes(sc, results_by_id=results) == 0

    def test_agreed_records_correct(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={"checker_model": "gpt-5", "verdict": "agreed"},
            cf_agreed=True,
        )}
        n = record_cross_family_outcomes(sc, results_by_id=results)
        assert n == 1
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gpt-5")
        ec = cell.events.get(EventType.CROSS_FAMILY_CHECK)
        assert ec is not None
        assert ec.correct == 1

    def test_disputed_records_incorrect(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={
                "checker_model": "gpt-5",
                "verdict": "disputed — conservative override",
                "checker_ruling": "This is a false positive because...",
                "trigger": "nonce_leaked",
            },
            cf_disputed=True,
        )}
        n = record_cross_family_outcomes(sc, results_by_id=results)
        assert n == 1
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gpt-5")
        ec = cell.events.get(EventType.CROSS_FAMILY_CHECK)
        assert ec is not None
        assert ec.incorrect == 1

    def test_disputed_captures_sample(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        sc.retain_samples = True
        results = {"F-001": _make_result(
            "F-001",
            cf_check={
                "checker_model": "gpt-5",
                "verdict": "disputed — conservative override",
                "checker_ruling": "Actually safe due to bounds check",
                "trigger": "low_quality",
            },
            cf_disputed=True,
        )}
        record_cross_family_outcomes(sc, results_by_id=results)
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gpt-5")
        assert len(cell.disagreement_samples) == 1
        assert cell.disagreement_samples[0]["trigger"] == "low_quality"
        assert "bounds check" in cell.disagreement_samples[0]["checker_ruling"]

    def test_skips_same_family_fallback(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={
                "checker_model": "gemini-2.5-flash",
                "intended_model": "gpt-5",
                "verdict": "skipped — checker fell back to same family",
                "trigger": "nonce_leaked",
            },
        )}
        assert record_cross_family_outcomes(sc, results_by_id=results) == 0

    def test_decision_class_format(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            rule_id="py/sql-injection",
            cf_check={"checker_model": "gpt-5", "verdict": "agreed"},
            cf_agreed=True,
        )}
        record_cross_family_outcomes(sc, results_by_id=results)
        classes = {s.decision_class for s in sc.get_stats()}
        assert "agentic:py/sql-injection" in classes

    def test_multiple_findings_mixed(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {
            "F-001": _make_result(
                "F-001",
                cf_check={"checker_model": "gpt-5", "verdict": "agreed"},
                cf_agreed=True,
            ),
            "F-002": _make_result(
                "F-002",
                cf_check={
                    "checker_model": "gpt-5",
                    "verdict": "disputed — conservative override",
                },
                cf_disputed=True,
            ),
            "F-003": _make_result("F-003"),
        }
        n = record_cross_family_outcomes(sc, results_by_id=results)
        assert n == 2
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gpt-5")
        ec = cell.events[EventType.CROSS_FAMILY_CHECK]
        assert ec.correct == 1
        assert ec.incorrect == 1

    def test_disputed_derived_from_verdict_string(self, tmp_path: Path):
        """Verdict-string drives outcome even without top-level boolean."""
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={
                "checker_model": "gpt-5",
                "verdict": "disputed — conservative override",
            },
        )}
        n = record_cross_family_outcomes(sc, results_by_id=results)
        assert n == 1
        cell = next(s for s in sc.get_stats() if s.model == "gpt-5")
        assert cell.events[EventType.CROSS_FAMILY_CHECK].incorrect == 1

    def test_skips_empty_checker_model(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={"checker_model": "", "verdict": "agreed"},
            cf_agreed=True,
        )}
        assert record_cross_family_outcomes(sc, results_by_id=results) == 0

    def test_skips_none_checker_model(self, tmp_path: Path):
        sc = ModelScorecard(path=tmp_path / "sc.json")
        results = {"F-001": _make_result(
            "F-001",
            cf_check={"checker_model": None, "verdict": "agreed"},
            cf_agreed=True,
        )}
        assert record_cross_family_outcomes(sc, results_by_id=results) == 0
