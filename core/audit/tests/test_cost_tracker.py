"""Tests for core.audit.cost_tracker."""

from __future__ import annotations

import json

from core.audit.cost_tracker import PhaseCost, PhaseCostLedger


class TestPhaseCost:
    def test_defaults_zero(self):
        pc = PhaseCost()
        assert pc.wall_time_s == 0.0
        assert pc.calls == 0
        assert pc.cost_usd == 0.0

    def test_to_dict(self):
        pc = PhaseCost(wall_time_s=1.5, calls=3, cost_usd=0.05)
        d = pc.to_dict()
        assert d["wall_time_s"] == 1.5
        assert d["calls"] == 3
        assert d["cost_usd"] == 0.05


class TestCostTracker:
    def test_record_call(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.01, tokens_in=100, tokens_out=50)
        ct.record_call("review", cost_usd=0.02, tokens_in=200, tokens_out=100)
        assert ct.phases["review"].calls == 2
        assert ct.phases["review"].cost_usd == 0.03
        assert ct.phases["review"].tokens_in == 300
        assert ct.phases["review"].tokens_out == 150

    def test_total_cost(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.10)
        ct.record_call("refinement", cost_usd=0.05)
        ct.record_call("sweep", cost_usd=0.00)
        assert abs(ct.total_cost_usd - 0.15) < 1e-9

    def test_total_calls(self):
        ct = PhaseCostLedger()
        ct.record_call("review")
        ct.record_call("review")
        ct.record_call("sweep")
        assert ct.total_calls == 3

    def test_to_dict(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.01, wall_time_s=1.0)
        ct.record_call("sweep", cost_usd=0.00, wall_time_s=5.0)
        d = ct.to_dict()
        assert "phases" in d
        assert "totals" in d
        assert d["totals"]["calls"] == 2
        assert d["totals"]["cost_usd"] == 0.01

    def test_write(self, tmp_path):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.50)
        path = ct.write(tmp_path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["totals"]["cost_usd"] == 0.50

    def test_summary(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.10)
        ct.record_call("refinement", cost_usd=0.05)
        s = ct.summary()
        assert "$0.15" in s
        assert "review=" in s
        assert "refinement=" in s

    def test_phase_summary(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.10, wall_time_s=2.0)
        text = ct.phase_summary()
        assert "review" in text
        assert "2.0s" in text

    def test_start_end_phase(self):
        ct = PhaseCostLedger()
        ct.start_phase("review")
        ct.end_phase()
        assert "review" in ct.phases
        assert ct.phases["review"].wall_time_s >= 0.0

    def test_start_phase_ends_previous(self):
        ct = PhaseCostLedger()
        ct.start_phase("review")
        ct.start_phase("sweep")
        assert "review" in ct.phases
        assert ct._active_phase == "sweep"
        ct.end_phase()
        assert "sweep" in ct.phases

    def test_empty_tracker(self):
        ct = PhaseCostLedger()
        assert ct.total_cost_usd == 0.0
        assert ct.total_calls == 0
        s = ct.summary()
        assert "$0.00" in s

    def test_serializable(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.01)
        json.dumps(ct.to_dict())
