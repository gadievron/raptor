"""Tests for multi-model correlation engine."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.llm_analysis.correlation import correlate_results, _build_clusters


def _make_result(finding_id, analyses):
    """Build a result dict with multi_model_analyses."""
    return {
        "finding_id": finding_id,
        "rule_id": "sqli",
        "multi_model_analyses": analyses,
    }


def _make_analysis(model, exploitable, score=0.8, ruling="validated"):
    return {
        "model": model,
        "is_exploitable": exploitable,
        "exploitability_score": score,
        "ruling": ruling,
        "reasoning": f"{model} says {'yes' if exploitable else 'no'}",
    }


class TestCorrelateResults:
    def test_empty_input(self):
        result = correlate_results({})
        assert result["agreement_matrix"] == {}
        assert result["clusters"] == []
        assert result["unique_insights"] == []
        assert result["confidence_signals"] == {}
        assert result["summary"]["total_correlated"] == 0

    def test_skips_single_model_findings(self):
        results = {
            "f-001": _make_result("f-001", [
                _make_analysis("gemini", True),
            ]),
        }
        result = correlate_results(results)
        assert result["summary"]["total_correlated"] == 0

    def test_skips_findings_without_analyses(self):
        results = {
            "f-001": {"finding_id": "f-001", "is_exploitable": True},
        }
        result = correlate_results(results)
        assert result["summary"]["total_correlated"] == 0

    def test_unanimous_exploitable(self):
        results = {
            "f-001": _make_result("f-001", [
                _make_analysis("gemini", True),
                _make_analysis("gpt-5", True),
            ]),
        }
        result = correlate_results(results)
        assert result["confidence_signals"]["f-001"] == "high"
        assert result["summary"]["agreed"] == 1
        assert result["summary"]["disputed"] == 0
        assert result["summary"]["models"] == ["gemini", "gpt-5"]

    def test_unanimous_not_exploitable(self):
        results = {
            "f-001": _make_result("f-001", [
                _make_analysis("gemini", False),
                _make_analysis("gpt-5", False),
            ]),
        }
        result = correlate_results(results)
        assert result["confidence_signals"]["f-001"] == "high-negative"
        assert result["summary"]["agreed"] == 1

    def test_disputed(self):
        results = {
            "f-001": _make_result("f-001", [
                _make_analysis("gemini", True),
                _make_analysis("gpt-5", False),
            ]),
        }
        result = correlate_results(results)
        assert result["confidence_signals"]["f-001"] == "disputed"
        assert result["summary"]["disputed"] == 1

    def test_disputed_unique_insights(self):
        results = {
            "f-001": _make_result("f-001", [
                _make_analysis("gemini", True),
                _make_analysis("gpt-5", False),
                _make_analysis("claude", True),
            ]),
        }
        result = correlate_results(results)
        assert result["confidence_signals"]["f-001"] == "disputed"
        # gpt-5 is the minority (1 not-exploitable vs 2 exploitable)
        assert len(result["unique_insights"]) == 1
        assert result["unique_insights"][0]["model"] == "gpt-5"
        assert result["unique_insights"][0]["verdict"] is False

    def test_agreement_matrix_structure(self):
        results = {
            "f-001": _make_result("f-001", [
                _make_analysis("gemini", True, score=0.9),
                _make_analysis("gpt-5", True, score=0.7),
            ]),
        }
        result = correlate_results(results)
        matrix = result["agreement_matrix"]
        assert "f-001" in matrix
        assert "gemini" in matrix["f-001"]
        assert matrix["f-001"]["gemini"]["is_exploitable"] is True
        assert matrix["f-001"]["gemini"]["exploitability_score"] == 0.9

    def test_multiple_findings(self):
        results = {
            "f-001": _make_result("f-001", [
                _make_analysis("gemini", True),
                _make_analysis("gpt-5", True),
            ]),
            "f-002": _make_result("f-002", [
                _make_analysis("gemini", False),
                _make_analysis("gpt-5", True),
            ]),
        }
        result = correlate_results(results)
        assert result["summary"]["total_correlated"] == 2
        assert result["summary"]["agreed"] == 1
        assert result["summary"]["disputed"] == 1

    def test_reasoning_truncated(self):
        long_reasoning = "x" * 500
        results = {
            "f-001": _make_result("f-001", [
                {"model": "gemini", "is_exploitable": True,
                 "exploitability_score": 0.9, "ruling": "ok",
                 "reasoning": long_reasoning},
                {"model": "gpt-5", "is_exploitable": False,
                 "exploitability_score": 0.2, "ruling": "no",
                 "reasoning": "short"},
            ]),
        }
        result = correlate_results(results)
        for insight in result["unique_insights"]:
            assert len(insight["reasoning"]) <= 200


class TestBuildClusters:
    def test_no_clusters_for_singletons(self):
        matrix = {
            "f-001": {"gemini": {"is_exploitable": True}},
        }
        clusters = _build_clusters(matrix, {})
        assert clusters == []

    def test_same_pattern_clusters(self):
        matrix = {
            "f-001": {"gemini": {"is_exploitable": True}, "gpt-5": {"is_exploitable": True}},
            "f-002": {"gemini": {"is_exploitable": True}, "gpt-5": {"is_exploitable": True}},
        }
        results = {
            "f-001": {"rule_id": "sqli"},
            "f-002": {"rule_id": "sqli"},
        }
        clusters = _build_clusters(matrix, results)
        assert len(clusters) == 1
        assert clusters[0]["pattern"] == "unanimous"
        assert clusters[0]["models_agreed"] is True
        assert sorted(clusters[0]["finding_ids"]) == ["f-001", "f-002"]
        assert "sqli" in clusters[0]["shared_rules"]

    def test_different_patterns_no_cluster(self):
        matrix = {
            "f-001": {"gemini": {"is_exploitable": True}, "gpt-5": {"is_exploitable": True}},
            "f-002": {"gemini": {"is_exploitable": True}, "gpt-5": {"is_exploitable": False}},
        }
        clusters = _build_clusters(matrix, {})
        assert clusters == []

    def test_split_pattern_cluster(self):
        matrix = {
            "f-001": {"gemini": {"is_exploitable": True}, "gpt-5": {"is_exploitable": False}},
            "f-002": {"gemini": {"is_exploitable": True}, "gpt-5": {"is_exploitable": False}},
        }
        clusters = _build_clusters(matrix, {})
        assert len(clusters) == 1
        assert clusters[0]["pattern"] == "split"
        assert clusters[0]["models_agreed"] is False

    def test_multiple_clusters(self):
        matrix = {
            "f-001": {"gemini": {"is_exploitable": True}, "gpt-5": {"is_exploitable": True}},
            "f-002": {"gemini": {"is_exploitable": True}, "gpt-5": {"is_exploitable": True}},
            "f-003": {"gemini": {"is_exploitable": False}, "gpt-5": {"is_exploitable": False}},
            "f-004": {"gemini": {"is_exploitable": False}, "gpt-5": {"is_exploitable": False}},
        }
        clusters = _build_clusters(matrix, {})
        assert len(clusters) == 2
