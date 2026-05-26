"""Tests for LLM triage stage."""

from __future__ import annotations


from packages.sca.llm.schemas import TriageResult
from packages.sca.llm.triage import _trim_for_llm, triage_findings


class TestTrimForLLM:
    def test_keeps_relevant_keys(self):
        rows = [
            {
                "id": "F-001",
                "finding_id": "F-001",
                "vuln_type": "sca:vulnerable_dependency",
                "severity": "critical",
                "description": "Known RCE",
                "irrelevant_key": "should be dropped",
                "sca": {
                    "ecosystem": "npm",
                    "name": "evil-pkg",
                    "version": "1.0.0",
                    "reachability": "imported",
                    "in_kev": True,
                    "epss": 0.95,
                    "supply_chain_kind": None,
                    "extra_junk": "should be dropped",
                },
            },
        ]
        trimmed = _trim_for_llm(rows)
        assert len(trimmed) == 1
        t = trimmed[0]
        assert "id" in t
        assert "severity" in t
        assert "irrelevant_key" not in t
        assert t["sca"]["ecosystem"] == "npm"
        assert "extra_junk" not in t.get("sca", {})

    def test_caps_at_limit(self):
        rows = [{"id": f"F-{i}", "severity": "low"} for i in range(100)]
        trimmed = _trim_for_llm(rows, limit=10)
        assert len(trimmed) == 10

    def test_empty_input(self):
        assert _trim_for_llm([]) == []

    def test_sca_not_dict_handled(self):
        rows = [{"id": "F-001", "sca": "not a dict"}]
        trimmed = _trim_for_llm(rows)
        assert len(trimmed) == 1


class TestTriageFindings:
    def test_empty_findings_returns_empty_result(self):
        result = triage_findings(object(), [], None)
        assert isinstance(result, TriageResult)
        assert result.items == []
        assert "No findings" in result.project_context_summary
