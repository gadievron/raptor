"""Tests for ``core/run/estimator.py`` — scorecard-derived
cost-and-time estimator."""

from __future__ import annotations

import json

from core.run.estimator import (
    RunEstimate,
    estimate_from_scorecard,
    format_estimate,
)


class TestEstimateFromScorecard:
    """Scorecard-derived estimates use real per-model call history."""

    def _write_scorecard(self, path, model, calls, cost_usd, latency_ms_sum):
        data = {
            "version": 2,
            "models": {
                model: {
                    "analysis": {
                        "first_seen_at": "2026-01-01T00:00:00Z",
                        "last_seen_at": "2026-06-01T00:00:00Z",
                        "model_version": model,
                        "policy_override": "auto",
                        "events": {},
                        "calls": calls,
                        "cost_usd": cost_usd,
                        "tokens": 0,
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "latency_ms_sum": latency_ms_sum,
                        "latency_ms_max": 0,
                    },
                },
            },
        }
        path.write_text(json.dumps(data), encoding="utf-8")

    def test_returns_none_when_no_scorecard(self, tmp_path):
        sc_path = tmp_path / "nonexistent.json"
        est = estimate_from_scorecard(
            "test-model", 20, scorecard_path=sc_path,
        )
        assert est is None

    def test_returns_none_when_too_few_calls(self, tmp_path):
        sc_path = tmp_path / "sc.json"
        self._write_scorecard(sc_path, "test-model", 3, 0.30, 30000)
        est = estimate_from_scorecard(
            "test-model", 20, scorecard_path=sc_path,
        )
        assert est is None

    def test_returns_none_for_zero_findings(self, tmp_path):
        sc_path = tmp_path / "sc.json"
        self._write_scorecard(sc_path, "test-model", 100, 10.0, 500000)
        est = estimate_from_scorecard(
            "test-model", 0, scorecard_path=sc_path,
        )
        assert est is None

    def test_returns_estimate_with_sufficient_data(self, tmp_path):
        sc_path = tmp_path / "sc.json"
        self._write_scorecard(sc_path, "test-model", 100, 10.0, 500000)
        est = estimate_from_scorecard(
            "test-model", 20, max_parallel=1, scorecard_path=sc_path,
        )
        assert est is not None
        assert est.source == "scorecard"
        assert est.cost_low > 0
        assert est.cost_high > est.cost_low
        assert est.time_low > 0

    def test_parallelism_reduces_time(self, tmp_path):
        sc_path = tmp_path / "sc.json"
        self._write_scorecard(sc_path, "test-model", 100, 10.0, 500000)
        est_1 = estimate_from_scorecard(
            "test-model", 20, max_parallel=1, scorecard_path=sc_path,
        )
        est_3 = estimate_from_scorecard(
            "test-model", 20, max_parallel=3, scorecard_path=sc_path,
        )
        assert est_1 is not None
        assert est_3 is not None
        assert est_3.time_high < est_1.time_high

    def test_cost_unaffected_by_parallelism(self, tmp_path):
        sc_path = tmp_path / "sc.json"
        self._write_scorecard(sc_path, "test-model", 100, 10.0, 500000)
        est_1 = estimate_from_scorecard(
            "test-model", 20, max_parallel=1, scorecard_path=sc_path,
        )
        est_3 = estimate_from_scorecard(
            "test-model", 20, max_parallel=3, scorecard_path=sc_path,
        )
        assert est_1 is not None
        assert est_3 is not None
        assert est_1.cost_low == est_3.cost_low
        assert est_1.cost_high == est_3.cost_high

    def test_unknown_model_returns_none(self, tmp_path):
        sc_path = tmp_path / "sc.json"
        self._write_scorecard(sc_path, "test-model", 100, 10.0, 500000)
        est = estimate_from_scorecard(
            "other-model", 20, scorecard_path=sc_path,
        )
        assert est is None


class TestFormatEstimate:
    """Renderer: None → empty string; populated → operator-facing
    one-liner."""

    def test_none_returns_empty_string(self):
        assert format_estimate(None) == ""

    def test_scorecard_source_renders_model_name(self):
        est = RunEstimate(
            cost_low=2, cost_high=4, time_low=5, time_high=8,
            target_type="claude-opus-4-7 (scorecard)", source="scorecard",
        )
        s = format_estimate(est)
        assert "from scorecard" in s
        assert "claude-opus-4-7" in s

    def test_collapsed_range_renders_single_value(self):
        est = RunEstimate(
            cost_low=30, cost_high=30, time_low=60, time_high=60,
            target_type="test-model (scorecard)",
        )
        s = format_estimate(est)
        assert s == "Expected: $30, 60 min (test-model, from scorecard)"

    def test_cost_only_renders_without_time(self):
        est = RunEstimate(
            cost_low=10, cost_high=20, time_low=0, time_high=0,
            target_type="test-model (scorecard)",
        )
        s = format_estimate(est)
        assert s == "Expected: $10-$20 (test-model, from scorecard)"

    def test_time_only_renders_without_cost(self):
        est = RunEstimate(
            cost_low=0, cost_high=0, time_low=15, time_high=30,
            target_type="test-model (scorecard)",
        )
        s = format_estimate(est)
        assert s == "Expected: 15-30 min (test-model, from scorecard)"

    def test_both_zero_returns_empty_string(self):
        est = RunEstimate(
            cost_low=0, cost_high=0, time_low=0, time_high=0,
            target_type="both-zero",
        )
        assert format_estimate(est) == ""
