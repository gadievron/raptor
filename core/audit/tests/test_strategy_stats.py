"""Tests for core.audit.strategy_stats."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.strategy_stats import (
    aggregate_strategy_stats,
    compute_strategy_weights,
    find_project_log_dirs,
    load_strategy_weights,
)


def _write_audit_log(log_dir: Path, entries: list) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    with open(log_dir / ".audit-log.jsonl", "w") as f:
        f.writelines(json.dumps(entry) + "\n" for entry in entries)


class TestAggregateStrategyStats:
    def test_counts_wins_and_misses(self, tmp_path):
        _write_audit_log(tmp_path / "run1", [
            {"action": "orchestrator_review", "status": "finding",
             "strategies": ["input_handling", "general"]},
            {"action": "orchestrator_review", "status": "clean",
             "strategies": ["input_handling", "general"]},
            {"action": "orchestrator_review", "status": "suspicious",
             "strategies": ["memory"]},
        ])
        stats = aggregate_strategy_stats([tmp_path / "run1"])
        assert stats["input_handling"]["wins"] == 1
        assert stats["input_handling"]["misses"] == 1
        assert stats["input_handling"]["total"] == 2
        assert stats["general"]["wins"] == 1
        assert stats["general"]["misses"] == 1
        assert stats["memory"]["wins"] == 1
        assert stats["memory"]["misses"] == 0

    def test_ignores_non_review_entries(self, tmp_path):
        _write_audit_log(tmp_path / "run1", [
            {"action": "feedback", "status": "finding",
             "strategies": ["input_handling"]},
            {"action": "orchestrator_review", "status": "finding",
             "strategies": ["general"]},
        ])
        stats = aggregate_strategy_stats([tmp_path / "run1"])
        assert "input_handling" not in stats
        assert stats["general"]["wins"] == 1

    def test_ignores_entries_without_strategies(self, tmp_path):
        _write_audit_log(tmp_path / "run1", [
            {"action": "orchestrator_review", "status": "finding"},
        ])
        stats = aggregate_strategy_stats([tmp_path / "run1"])
        assert stats == {}

    def test_aggregates_across_multiple_dirs(self, tmp_path):
        _write_audit_log(tmp_path / "run1", [
            {"action": "orchestrator_review", "status": "finding",
             "strategies": ["input_handling"]},
        ])
        _write_audit_log(tmp_path / "run2", [
            {"action": "orchestrator_review", "status": "clean",
             "strategies": ["input_handling"]},
        ])
        stats = aggregate_strategy_stats([
            tmp_path / "run1", tmp_path / "run2",
        ])
        assert stats["input_handling"]["total"] == 2
        assert stats["input_handling"]["wins"] == 1
        assert stats["input_handling"]["misses"] == 1

    def test_empty_dirs(self, tmp_path):
        stats = aggregate_strategy_stats([tmp_path / "nonexistent"])
        assert stats == {}

    def test_error_status_excluded(self, tmp_path):
        _write_audit_log(tmp_path / "run1", [
            {"action": "orchestrator_review", "status": "error",
             "strategies": ["general"]},
        ])
        stats = aggregate_strategy_stats([tmp_path / "run1"])
        assert stats["general"]["total"] == 1
        assert stats["general"]["wins"] == 0
        assert stats["general"]["misses"] == 0


class TestComputeStrategyWeights:
    def test_high_win_rate_boosts(self):
        stats = {"input_handling": {"wins": 8, "misses": 2, "total": 10}}
        weights = compute_strategy_weights(stats, min_samples=5)
        assert weights["input_handling"] > 1.0

    def test_low_win_rate_demotes(self):
        stats = {"general": {"wins": 1, "misses": 19, "total": 20}}
        weights = compute_strategy_weights(stats, min_samples=5)
        assert weights["general"] < 1.0

    def test_insufficient_samples_default(self):
        stats = {"memory": {"wins": 2, "misses": 1, "total": 3}}
        weights = compute_strategy_weights(stats, min_samples=10)
        assert weights["memory"] == 1.0

    def test_weight_bounds(self):
        stats = {
            "always_wins": {"wins": 100, "misses": 0, "total": 100},
            "always_loses": {"wins": 0, "misses": 100, "total": 100},
        }
        weights = compute_strategy_weights(stats, min_samples=5)
        assert 0.5 <= weights["always_loses"] <= 0.6
        assert 1.9 <= weights["always_wins"] <= 2.0


class TestFindProjectLogDirs:
    def test_finds_sibling_dirs(self, tmp_path):
        _write_audit_log(tmp_path / "run1", [
            {"action": "orchestrator_review", "status": "clean",
             "strategies": ["general"]},
        ])
        _write_audit_log(tmp_path / "run2", [
            {"action": "orchestrator_review", "status": "finding",
             "strategies": ["general"]},
        ])
        current = tmp_path / "run3"
        current.mkdir()
        dirs = find_project_log_dirs(current)
        assert len(dirs) == 2
        assert current not in dirs

    def test_excludes_current_dir(self, tmp_path):
        _write_audit_log(tmp_path / "current", [
            {"action": "orchestrator_review", "status": "clean",
             "strategies": ["general"]},
        ])
        dirs = find_project_log_dirs(tmp_path / "current")
        assert dirs == []

    def test_respects_max_dirs(self, tmp_path):
        for i in range(5):
            _write_audit_log(tmp_path / f"run{i}", [
                {"action": "orchestrator_review", "status": "clean",
                 "strategies": ["general"]},
            ])
        current = tmp_path / "current"
        current.mkdir()
        dirs = find_project_log_dirs(current, max_dirs=2)
        assert len(dirs) == 2

    def test_survives_sibling_deleted_before_sort(self, tmp_path, monkeypatch):
        """A sibling deleted between iterdir() and the mtime sort (e.g.
        concurrent `/project clean`) must not crash the lookup."""
        import shutil

        from core.audit import strategy_stats as ss

        _write_audit_log(tmp_path / "run1", [
            {"action": "orchestrator_review", "status": "clean",
             "strategies": ["general"]},
        ])
        _write_audit_log(tmp_path / "run2", [
            {"action": "orchestrator_review", "status": "clean",
             "strategies": ["general"]},
        ])
        current = tmp_path / "current"
        current.mkdir()

        doomed = tmp_path / "run1"
        real_safe_mtime = ss._safe_mtime

        def racy_mtime(p):
            # Simulate the reaper winning the race: run1 vanishes
            # right before its mtime is read.
            if p == doomed and doomed.exists():
                shutil.rmtree(doomed)
            return real_safe_mtime(p)

        monkeypatch.setattr(ss, "_safe_mtime", racy_mtime)
        dirs = find_project_log_dirs(current)
        assert tmp_path / "run2" in dirs

    def test_safe_mtime_missing_path(self, tmp_path):
        from core.audit.strategy_stats import _safe_mtime
        assert _safe_mtime(tmp_path / "gone") == 0.0


class TestLoadStrategyWeights:
    def test_returns_none_without_data(self, tmp_path):
        result = load_strategy_weights(tmp_path / "empty")
        assert result is None

    def test_returns_weights_with_data(self, tmp_path):
        for i in range(3):
            _write_audit_log(tmp_path / f"run{i}", [
                {"action": "orchestrator_review", "status": "finding",
                 "strategies": ["input_handling"]},
            ] * 5)
        current = tmp_path / "current"
        current.mkdir()
        result = load_strategy_weights(current, min_samples=5)
        assert result is not None
        assert "input_handling" in result
        assert result["input_handling"] > 1.0


class TestStrategyWeightInScoring:
    def test_high_weight_boosts_score(self):
        from core.audit.priority import score_functions

        gaps = [
            {"file": "a.c", "name": "fn1", "priority": 0, "sloc": 50,
             "strategies": ["input_handling"]},
            {"file": "a.c", "name": "fn2", "priority": 0, "sloc": 50,
             "strategies": ["general"]},
        ]
        weights = {"input_handling": 2.0, "general": 0.5}
        scored = score_functions(gaps, strategy_weights=weights)
        by_name = {g["name"]: g for g in scored}
        assert by_name["fn1"]["priority_score"] > by_name["fn2"]["priority_score"]

    def test_no_weights_no_effect(self):
        from core.audit.priority import score_functions

        gaps = [
            {"file": "a.c", "name": "fn1", "priority": 0, "sloc": 50,
             "strategies": ["input_handling"]},
        ]
        scored_with = score_functions(gaps, strategy_weights={"input_handling": 1.0})
        scored_without = score_functions(gaps, strategy_weights=None)
        assert scored_with[0]["priority_score"] == scored_without[0]["priority_score"]
