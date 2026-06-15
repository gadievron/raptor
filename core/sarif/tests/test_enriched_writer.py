"""Tests for core.sarif.enriched_writer."""

import json

import pytest

from core.sarif.enriched_writer import (
    _build_raptor_properties,
    _verdict_from_analysis,
    _reachability_from_analysis,
    build_enriched_sarif,
    write_enriched_sarif,
)


# ---------------------------------------------------------------------------
# Verdict mapping
# ---------------------------------------------------------------------------

class TestVerdictFromAnalysis:

    def test_suppressed(self):
        f = {"analysis": {"reachability_suppression": True}}
        assert _verdict_from_analysis(f) == "suppressed"

    def test_exploitable(self):
        f = {"exploitable": True, "analysis": {"is_true_positive": True}}
        assert _verdict_from_analysis(f) == "exploitable"

    def test_confirmed(self):
        f = {"exploitable": False, "analysis": {"is_true_positive": True}}
        assert _verdict_from_analysis(f) == "confirmed"

    def test_ruled_out(self):
        f = {"analysis": {"is_true_positive": False}}
        assert _verdict_from_analysis(f) == "ruled_out"

    def test_not_analyzed(self):
        assert _verdict_from_analysis({}) == "not_analyzed"

    def test_suppressed_beats_exploitable(self):
        f = {
            "exploitable": True,
            "analysis": {"reachability_suppression": True, "is_true_positive": True},
        }
        assert _verdict_from_analysis(f) == "suppressed"


class TestReachabilityFromAnalysis:

    def test_explicit_verdict(self):
        f = {"analysis": {"reachability_verdict": "symbol_present"}}
        assert _reachability_from_analysis(f) == "symbol_present"

    def test_suppressed_implies_absent(self):
        f = {"analysis": {"reachability_suppression": True}}
        assert _reachability_from_analysis(f) == "absent"

    def test_default(self):
        assert _reachability_from_analysis({}) == "not_evaluated"


# ---------------------------------------------------------------------------
# Properties builder
# ---------------------------------------------------------------------------

class TestBuildRaptorProperties:

    def test_minimal(self):
        verdict, props = _build_raptor_properties({})
        assert verdict == "not_analyzed"
        assert props["verdict"] == "not_analyzed"
        assert props["reachability"] == "not_evaluated"
        assert "source_type" not in props

    def test_source_type(self):
        f = {"source_type": "dependency"}
        _, props = _build_raptor_properties(f)
        assert props["source_type"] == "dependency"

    def test_cwe_inferred(self):
        f = {"_cwe_inferred": True}
        _, props = _build_raptor_properties(f)
        assert props["cwe_inferred"] is True

    def test_reasoning_truncated(self):
        f = {"analysis": {"reasoning": "x" * 1000}}
        _, props = _build_raptor_properties(f)
        assert len(props["reasoning"]) == 500

    def test_exploitability_score(self):
        f = {"exploitability_score": 0.85}
        _, props = _build_raptor_properties(f)
        assert props["exploitability_score"] == 0.85

    def test_zero_score_omitted(self):
        f = {"exploitability_score": 0.0}
        _, props = _build_raptor_properties(f)
        assert "exploitability_score" not in props

    def test_exploit_fields(self):
        f = {"has_exploit": True, "exploit_compiled": True}
        _, props = _build_raptor_properties(f)
        assert props["has_exploit"] is True
        assert props["exploit_compiled"] is True

    def test_has_dataflow(self):
        _, props = _build_raptor_properties({"has_dataflow": True})
        assert props["has_dataflow"] is True

    def test_has_dataflow_omitted_when_false(self):
        _, props = _build_raptor_properties({"has_dataflow": False})
        assert "has_dataflow" not in props

    def test_is_exploitable_from_analysis(self):
        f = {"analysis": {"is_exploitable": True}}
        _, props = _build_raptor_properties(f)
        assert props["is_exploitable"] is True

    def test_is_exploitable_false_emitted(self):
        f = {"analysis": {"is_exploitable": False}}
        _, props = _build_raptor_properties(f)
        assert props["is_exploitable"] is False

    def test_analysis_none_handled(self):
        f = {"analysis": None}
        verdict, props = _build_raptor_properties(f)
        assert verdict == "not_analyzed"
        assert "is_exploitable" not in props


# ---------------------------------------------------------------------------
# Full document builder
# ---------------------------------------------------------------------------

class TestBuildEnrichedSarif:

    @pytest.fixture()
    def exploitable_finding(self):
        return {
            "finding_id": "abc123",
            "rule_id": "CWE-79",
            "file_path": "src/app.py",
            "start_line": 42,
            "end_line": 42,
            "message": "XSS in template rendering",
            "level": "error",
            "tool": "Semgrep",
            "cwe_id": "CWE-79",
            "exploitable": True,
            "exploitability_score": 0.9,
            "analysis": {
                "is_true_positive": True,
                "is_exploitable": True,
                "reasoning": "User input flows to template without escaping",
            },
        }

    @pytest.fixture()
    def suppressed_finding(self):
        return {
            "finding_id": "def456",
            "rule_id": "CWE-120",
            "file_path": "src/utils.c",
            "start_line": 10,
            "message": "Buffer overflow in parse_input",
            "level": "warning",
            "tool": "CodeQL",
            "analysis": {
                "reachability_suppression": True,
                "reachability_verdict": "absent",
            },
        }

    def test_schema_and_version(self, exploitable_finding):
        doc = build_enriched_sarif([exploitable_finding], tool_version="1.0.0")
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc

    def test_grouped_by_tool(self, exploitable_finding, suppressed_finding):
        doc = build_enriched_sarif(
            [exploitable_finding, suppressed_finding], tool_version="1.0.0",
        )
        assert len(doc["runs"]) == 2
        tool_names = {r["tool"]["driver"]["name"] for r in doc["runs"]}
        assert tool_names == {"Semgrep", "CodeQL"}

    def test_raptor_properties_on_result(self, exploitable_finding):
        doc = build_enriched_sarif([exploitable_finding], tool_version="1.0.0")
        result = doc["runs"][0]["results"][0]
        raptor = result["properties"]["raptor"]
        assert raptor["verdict"] == "exploitable"
        assert raptor["exploitability_score"] == 0.9

    def test_fingerprint_emitted(self, exploitable_finding):
        doc = build_enriched_sarif([exploitable_finding], tool_version="1.0.0")
        result = doc["runs"][0]["results"][0]
        assert result["fingerprints"]["matchBasedId/v1"] == "abc123"

    def test_suppression_emitted(self, suppressed_finding):
        doc = build_enriched_sarif([suppressed_finding], tool_version="1.0.0")
        result = doc["runs"][0]["results"][0]
        assert len(result["suppressions"]) == 1
        assert "binary-oracle" in result["suppressions"][0]["justification"]

    def test_rules_deduplicated(self):
        findings = [
            {"rule_id": "R1", "file_path": "a.py", "start_line": 1, "message": "m", "tool": "T"},
            {"rule_id": "R1", "file_path": "b.py", "start_line": 2, "message": "m", "tool": "T"},
        ]
        doc = build_enriched_sarif(findings, tool_version="1.0.0")
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "R1"

    def test_empty_findings(self):
        doc = build_enriched_sarif([], tool_version="1.0.0")
        assert doc["runs"] == []

    def test_cwe_in_rule_properties(self, exploitable_finding):
        doc = build_enriched_sarif([exploitable_finding], tool_version="1.0.0")
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert rules[0]["properties"]["cwe"] == ["CWE-79"]

    def test_snippet_from_code_field(self):
        f = {
            "rule_id": "R1", "file_path": "a.py", "start_line": 1,
            "message": "m", "tool": "T", "code": "x = 1\ny = 2",
        }
        doc = build_enriched_sarif([f], tool_version="1.0.0")
        region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["snippet"]["text"] == "x = 1\ny = 2"

    def test_no_suppression_for_non_suppressed(self, exploitable_finding):
        doc = build_enriched_sarif([exploitable_finding], tool_version="1.0.0")
        result = doc["runs"][0]["results"][0]
        assert "suppressions" not in result

    def test_start_line_zero_becomes_one(self):
        f = {"rule_id": "R1", "file_path": "a.py", "start_line": 0,
             "message": "m", "tool": "T"}
        doc = build_enriched_sarif([f], tool_version="1.0.0")
        region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 1

    def test_invalid_level_clamped_to_warning(self):
        f = {"rule_id": "R1", "file_path": "a.py", "start_line": 1,
             "message": "m", "tool": "T", "level": "critical"}
        doc = build_enriched_sarif([f], tool_version="1.0.0")
        assert doc["runs"][0]["results"][0]["level"] == "warning"

    def test_valid_level_preserved(self):
        f = {"rule_id": "R1", "file_path": "a.py", "start_line": 1,
             "message": "m", "tool": "T", "level": "error"}
        doc = build_enriched_sarif([f], tool_version="1.0.0")
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_none_fields_handled(self):
        f = {"rule_id": None, "file_path": None, "start_line": None,
             "message": None, "tool": None, "analysis": None}
        doc = build_enriched_sarif([f], tool_version="1.0.0")
        result = doc["runs"][0]["results"][0]
        assert result["ruleId"] == "unknown"
        assert result["message"]["text"] == ""
        assert result["level"] == "warning"

    def test_is_exploitable_in_raptor_properties(self, exploitable_finding):
        doc = build_enriched_sarif([exploitable_finding], tool_version="1.0.0")
        raptor = doc["runs"][0]["results"][0]["properties"]["raptor"]
        assert raptor["is_exploitable"] is True


# ---------------------------------------------------------------------------
# Atomic file writer
# ---------------------------------------------------------------------------

class TestWriteEnrichedSarif:

    def test_writes_valid_json(self, tmp_path):
        findings = [
            {
                "finding_id": "f1",
                "rule_id": "R1",
                "file_path": "a.py",
                "start_line": 1,
                "message": "test",
                "tool": "T",
            },
        ]
        out = tmp_path / "enriched.sarif"
        count = write_enriched_sarif(findings, out, tool_version="1.0.0")
        assert count == 1
        doc = json.loads(out.read_text())
        assert doc["version"] == "2.1.0"

    def test_creates_parent_dirs(self, tmp_path):
        out = tmp_path / "sub" / "dir" / "enriched.sarif"
        write_enriched_sarif([], out, tool_version="1.0.0")
        assert out.exists()

    def test_atomic_write_no_leftover(self, tmp_path):
        out = tmp_path / "enriched.sarif"
        write_enriched_sarif([], out, tool_version="1.0.0")
        assert not (tmp_path / "enriched.sarif.tmp").exists()


# ---------------------------------------------------------------------------
# Round-trip: enriched SARIF can be re-parsed
# ---------------------------------------------------------------------------

class TestRoundTrip:

    def test_enriched_sarif_is_reparsable(self, tmp_path):
        from core.sarif.parser import parse_sarif_findings

        findings = [
            {
                "finding_id": "rt1",
                "rule_id": "CWE-89",
                "file_path": "src/db.py",
                "start_line": 55,
                "end_line": 57,
                "message": "SQL injection via user input",
                "level": "error",
                "tool": "Semgrep",
                "cwe_id": "CWE-89",
                "exploitable": True,
                "analysis": {"is_true_positive": True},
            },
        ]
        out = tmp_path / "round-trip.sarif"
        write_enriched_sarif(findings, out, tool_version="1.0.0")
        reparsed = parse_sarif_findings(out)
        assert len(reparsed) == 1
        assert reparsed[0]["rule_id"] == "CWE-89"
        assert reparsed[0]["file"] == "src/db.py"
        assert reparsed[0]["startLine"] == 55
