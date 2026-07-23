"""Tests for cross-run verdict stability producer."""

from __future__ import annotations

import json
from pathlib import Path

from core.llm.scorecard.scorecard import EventType, ModelScorecard
from core.llm.scorecard.stability import (
    _find_prior_run,
    _targets_match,
    record_cross_run_stability,
)


def _write_run_metadata(run_dir: Path, *, target: str = "/tmp/target",
                        status: str = "completed", command: str = "agentic"):
    meta = {"target": target, "status": status, "command": command,
            "timestamp": "2026-07-22T00:00:00Z"}
    (run_dir / ".raptor-run.json").write_text(json.dumps(meta))


def _write_report(run_dir: Path, results: list):
    (run_dir / "orchestrated_report.json").write_text(
        json.dumps({"results": results})
    )


def _make_result(finding_id: str, *, is_exploitable: bool,
                 rule_id: str = "test-rule", model: str = "gemini-2.5-pro",
                 reasoning: str = "some reasoning"):
    return {
        "finding_id": finding_id,
        "is_exploitable": is_exploitable,
        "is_true_positive": is_exploitable,
        "rule_id": rule_id,
        "analysed_by": model,
        "resolved_model": model,
        "reasoning": reasoning,
    }


class TestFindPriorRun:
    def test_no_prior_run_returns_none(self, tmp_path: Path):
        current = tmp_path / "agentic_20260722_120000_pid1_1"
        current.mkdir()
        assert _find_prior_run(current) is None

    def test_finds_newest_completed(self, tmp_path: Path):
        older = tmp_path / "agentic_20260721_100000_pid1_1"
        older.mkdir()
        _write_run_metadata(older)
        _write_report(older, [])

        newer = tmp_path / "agentic_20260722_100000_pid2_2"
        newer.mkdir()
        _write_run_metadata(newer)
        _write_report(newer, [])

        current = tmp_path / "agentic_20260723_100000_pid3_3"
        current.mkdir()

        assert _find_prior_run(current) == newer

    def test_skips_incomplete_runs(self, tmp_path: Path):
        incomplete = tmp_path / "agentic_20260722_100000_pid1_1"
        incomplete.mkdir()
        _write_run_metadata(incomplete, status="running")
        _write_report(incomplete, [])

        completed = tmp_path / "agentic_20260721_100000_pid2_2"
        completed.mkdir()
        _write_run_metadata(completed)
        _write_report(completed, [])

        current = tmp_path / "agentic_20260723_100000_pid3_3"
        current.mkdir()

        assert _find_prior_run(current) == completed

    def test_skips_non_agentic_runs(self, tmp_path: Path):
        scan_run = tmp_path / "agentic_20260722_100000_pid1_1"
        scan_run.mkdir()
        _write_run_metadata(scan_run, command="scan")
        _write_report(scan_run, [])

        current = tmp_path / "agentic_20260723_100000_pid2_2"
        current.mkdir()

        assert _find_prior_run(current) is None

    def test_skips_missing_report(self, tmp_path: Path):
        no_report = tmp_path / "agentic_20260722_100000_pid1_1"
        no_report.mkdir()
        _write_run_metadata(no_report)

        current = tmp_path / "agentic_20260723_100000_pid2_2"
        current.mkdir()

        assert _find_prior_run(current) is None


class TestTargetsMatch:
    def test_same_target(self, tmp_path: Path):
        a = tmp_path / "run_a"
        a.mkdir()
        _write_run_metadata(a, target="/tmp/repo")
        b = tmp_path / "run_b"
        b.mkdir()
        _write_run_metadata(b, target="/tmp/repo")
        assert _targets_match(a, b) is True

    def test_different_target(self, tmp_path: Path):
        a = tmp_path / "run_a"
        a.mkdir()
        _write_run_metadata(a, target="/tmp/repo_a")
        b = tmp_path / "run_b"
        b.mkdir()
        _write_run_metadata(b, target="/tmp/repo_b")
        assert _targets_match(a, b) is False

    def test_missing_metadata(self, tmp_path: Path):
        a = tmp_path / "run_a"
        a.mkdir()
        b = tmp_path / "run_b"
        b.mkdir()
        assert _targets_match(a, b) is False


class TestRecordCrossRunStability:
    def _setup(self, tmp_path: Path, prior_results: list, current_results: dict,
               *, prior_target: str = "/tmp/target",
               current_target: str = "/tmp/target"):
        prior_dir = tmp_path / "agentic_20260722_100000_pid1_1"
        prior_dir.mkdir()
        _write_run_metadata(prior_dir, target=prior_target)
        _write_report(prior_dir, prior_results)

        current_dir = tmp_path / "agentic_20260723_100000_pid2_2"
        current_dir.mkdir()
        _write_run_metadata(current_dir, target=current_target)

        sc = ModelScorecard(path=tmp_path / "scorecard.json")
        return sc, current_dir, current_results

    def test_no_prior_run_returns_zero(self, tmp_path: Path):
        current_dir = tmp_path / "agentic_20260723_100000_pid1_1"
        current_dir.mkdir()
        sc = ModelScorecard(path=tmp_path / "scorecard.json")
        assert record_cross_run_stability(
            sc, out_dir=current_dir, results_by_id={},
        ) == 0

    def test_matching_verdicts_record_correct(self, tmp_path: Path):
        prior = [_make_result("F-001", is_exploitable=False)]
        current = {"F-001": _make_result("F-001", is_exploitable=False)}
        sc, current_dir, results = self._setup(tmp_path, prior, current)

        n = record_cross_run_stability(
            sc, out_dir=current_dir, results_by_id=results,
        )
        assert n == 1
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gemini-2.5-pro")
        ec = cell.events.get(EventType.CROSS_RUN_STABILITY)
        assert ec is not None
        assert ec.correct == 1

    def test_flipped_verdict_records_incorrect(self, tmp_path: Path):
        prior = [_make_result("F-001", is_exploitable=True)]
        current = {"F-001": _make_result("F-001", is_exploitable=False)}
        sc, current_dir, results = self._setup(tmp_path, prior, current)

        n = record_cross_run_stability(
            sc, out_dir=current_dir, results_by_id=results,
        )
        assert n == 1
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gemini-2.5-pro")
        ec = cell.events.get(EventType.CROSS_RUN_STABILITY)
        assert ec is not None
        assert ec.incorrect == 1

    def test_skips_unanalysed_findings(self, tmp_path: Path):
        prior = [_make_result("F-001", is_exploitable=True)]
        current = {"F-001": {"finding_id": "F-001", "is_exploitable": None,
                             "rule_id": "r", "analysed_by": "model"}}
        sc, current_dir, results = self._setup(tmp_path, prior, current)

        assert record_cross_run_stability(
            sc, out_dir=current_dir, results_by_id=results,
        ) == 0

    def test_skips_findings_not_in_prior(self, tmp_path: Path):
        prior = [_make_result("F-001", is_exploitable=True)]
        current = {"F-002": _make_result("F-002", is_exploitable=False)}
        sc, current_dir, results = self._setup(tmp_path, prior, current)

        assert record_cross_run_stability(
            sc, out_dir=current_dir, results_by_id=results,
        ) == 0

    def test_skips_different_target(self, tmp_path: Path):
        prior = [_make_result("F-001", is_exploitable=True)]
        current = {"F-001": _make_result("F-001", is_exploitable=False)}
        sc, current_dir, results = self._setup(
            tmp_path, prior, current,
            prior_target="/tmp/repo_a", current_target="/tmp/repo_b",
        )

        assert record_cross_run_stability(
            sc, out_dir=current_dir, results_by_id=results,
        ) == 0

    def test_sample_captures_reasoning(self, tmp_path: Path):
        prior = [_make_result("F-001", is_exploitable=True)]
        current = {"F-001": _make_result(
            "F-001", is_exploitable=False, reasoning="flipped because reasons",
        )}
        sc, current_dir, results = self._setup(tmp_path, prior, current)
        sc.retain_samples = True

        record_cross_run_stability(
            sc, out_dir=current_dir, results_by_id=results,
        )
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gemini-2.5-pro")
        assert len(cell.disagreement_samples) == 1
        assert cell.disagreement_samples[0]["this_verdict"] == "negative"
        assert cell.disagreement_samples[0]["prior_verdict"] == "positive"
        assert "flipped because reasons" in cell.disagreement_samples[0]["this_reasoning"]

    def test_decision_class_format(self, tmp_path: Path):
        prior = [_make_result("F-001", is_exploitable=True, rule_id="py/sql-injection")]
        current = {"F-001": _make_result(
            "F-001", is_exploitable=False, rule_id="py/sql-injection",
        )}
        sc, current_dir, results = self._setup(tmp_path, prior, current)

        record_cross_run_stability(
            sc, out_dir=current_dir, results_by_id=results,
        )
        stats = sc.get_stats()
        classes = {s.decision_class for s in stats}
        assert "agentic:py/sql-injection" in classes

    def test_none_scorecard_returns_zero(self, tmp_path: Path):
        assert record_cross_run_stability(
            None, out_dir=tmp_path, results_by_id={},
        ) == 0

    def test_skips_empty_model(self, tmp_path: Path):
        prior = [_make_result("F-001", is_exploitable=True)]
        current = {"F-001": _make_result("F-001", is_exploitable=True, model="")}
        sc, current_dir, results = self._setup(tmp_path, prior, current)
        assert record_cross_run_stability(
            sc, out_dir=current_dir, results_by_id=results,
        ) == 0

    def test_multiple_findings_mixed(self, tmp_path: Path):
        prior = [
            _make_result("F-001", is_exploitable=True),
            _make_result("F-002", is_exploitable=False),
            _make_result("F-003", is_exploitable=True),
        ]
        current = {
            "F-001": _make_result("F-001", is_exploitable=True),
            "F-002": _make_result("F-002", is_exploitable=True),
            "F-003": _make_result("F-003", is_exploitable=True),
        }
        sc, current_dir, results = self._setup(tmp_path, prior, current)

        n = record_cross_run_stability(
            sc, out_dir=current_dir, results_by_id=results,
        )
        assert n == 3
        stats = sc.get_stats()
        cell = next(s for s in stats if s.model == "gemini-2.5-pro")
        ec = cell.events.get(EventType.CROSS_RUN_STABILITY)
        assert ec is not None
        assert ec.correct == 2
        assert ec.incorrect == 1
