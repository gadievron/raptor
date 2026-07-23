"""Tests for the --max-cost-usd pre-flight gate (QoL #21).

Covers:
  1. ``raptor._extract_and_strip_max_cost_usd`` — argument-level
     parsing + scrubbing of the lifecycle-only flag.
  2. ``raptor._preflight_cost_gate`` — scorecard-derived estimate
     compared against the operator's declared budget.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_raptor():
    if "raptor" not in sys.modules:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor  # noqa: PLC0415
    return raptor


# ---------------------------------------------------------------------------
# Helper-level: _extract_and_strip_max_cost_usd
# ---------------------------------------------------------------------------


class TestExtractAndStrip:
    def test_returns_none_when_flag_absent(self):
        raptor = _import_raptor()
        cap, out = raptor._extract_and_strip_max_cost_usd(
            ["--repo", "/x", "--codeql"],
        )
        assert cap is None
        assert out == ["--repo", "/x", "--codeql"]

    def test_space_form_extracted_and_stripped(self):
        raptor = _import_raptor()
        cap, out = raptor._extract_and_strip_max_cost_usd(
            ["--max-cost-usd", "10", "--repo", "/x"],
        )
        assert cap == 10.0
        assert "--max-cost-usd" not in out
        assert "10" not in out
        assert out == ["--repo", "/x"]

    def test_equals_form_extracted_and_stripped(self):
        raptor = _import_raptor()
        cap, out = raptor._extract_and_strip_max_cost_usd(
            ["--repo", "/x", "--max-cost-usd=25.50"],
        )
        assert cap == 25.5
        assert out == ["--repo", "/x"]

    def test_fractional_dollar_amount_preserved(self):
        raptor = _import_raptor()
        cap, _ = raptor._extract_and_strip_max_cost_usd(
            ["--max-cost-usd", "0.0042"],
        )
        assert cap == pytest.approx(0.0042)

    def test_non_numeric_value_warns_and_strips(self, capsys):
        raptor = _import_raptor()
        cap, out = raptor._extract_and_strip_max_cost_usd(
            ["--max-cost-usd", "lots", "--repo", "/x"],
        )
        assert cap is None
        assert out == ["--repo", "/x"]
        captured = capsys.readouterr()
        assert "not a number" in captured.err

    def test_zero_value_warns_and_strips(self, capsys):
        raptor = _import_raptor()
        cap, out = raptor._extract_and_strip_max_cost_usd(
            ["--max-cost-usd", "0"],
        )
        assert cap is None
        assert out == []
        assert "> 0" in capsys.readouterr().err

    def test_negative_value_warns(self, capsys):
        raptor = _import_raptor()
        cap, _ = raptor._extract_and_strip_max_cost_usd(
            ["--max-cost-usd=-5"],
        )
        assert cap is None
        assert "> 0" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Pre-flight gate: _preflight_cost_gate
# ---------------------------------------------------------------------------


class TestPreflightCostGate:
    def test_no_target_does_not_fire(self, tmp_path):
        raptor = _import_raptor()
        assert raptor._preflight_cost_gate(None, 10.0, tmp_path) is False

    def test_no_scorecard_does_not_fire(self, tmp_path, monkeypatch):
        raptor = _import_raptor()
        monkeypatch.setattr(
            "core.run.estimator.estimate_from_scorecard",
            lambda *a, **kw: None,
        )
        target = tmp_path / "t"
        target.mkdir()
        (target / "configure.ac").write_text("")
        (target / "Makefile.am").write_text("")
        src = target / "src"
        src.mkdir()
        (src / "main.c").write_text("")
        assert raptor._preflight_cost_gate(str(target), 10.0, tmp_path) is False

    def test_estimate_within_cap_does_not_fire(self, tmp_path, monkeypatch):
        raptor = _import_raptor()
        from core.run.estimator import RunEstimate
        est = RunEstimate(
            cost_low=5, cost_high=8, time_low=10, time_high=15,
            target_type="test (scorecard)",
        )
        monkeypatch.setattr(
            "core.run.estimator.estimate_from_scorecard",
            lambda *a, **kw: est,
        )
        target = tmp_path / "t"
        target.mkdir()
        assert raptor._preflight_cost_gate(str(target), 10.0, tmp_path) is False

    def test_estimate_exceeds_cap_fires(self, tmp_path, monkeypatch, capsys):
        raptor = _import_raptor()
        from core.run.estimator import RunEstimate
        est = RunEstimate(
            cost_low=15, cost_high=25, time_low=10, time_high=15,
            target_type="test (scorecard)",
        )
        monkeypatch.setattr(
            "core.run.estimator.estimate_from_scorecard",
            lambda *a, **kw: est,
        )
        target = tmp_path / "t"
        target.mkdir()
        assert raptor._preflight_cost_gate(str(target), 10.0, tmp_path) is True
        captured = capsys.readouterr()
        assert "Pre-flight cost gate" in captured.err
        assert "$25.00" in captured.err
        assert "$10.00" in captured.err
