"""Tests for convert_validated_to_agent_format and _load_validated_findings."""

import pytest
from packages.llm_analysis.agent import convert_validated_to_agent_format


def _make_findings(*findings):
    """Helper to wrap findings in the expected envelope."""
    return {"stage": "E", "timestamp": "2026-01-01T00:00:00", "findings": list(findings)}


def _confirmed_finding(**overrides):
    """Create a minimal confirmed finding with defaults."""
    base = {
        "id": "FIND-0001",
        "file": "app.py",
        "function": "vuln",
        "line": 42,
        "vuln_type": "sql_injection",
        "status": "confirmed",
        "final_status": "confirmed",
    }
    base.update(overrides)
    return base


class TestSkipsRuledOut:
    def test_skips_ruled_out(self):
        data = _make_findings(
            _confirmed_finding(status="ruled_out"),
            _confirmed_finding(id="FIND-0002", status="confirmed"),
        )
        result = convert_validated_to_agent_format(data)
        assert len(result) == 1
        assert result[0]["finding_id"] == "FIND-0002"


class TestSkipsConfirmedBlocked:
    def test_skips_confirmed_blocked(self):
        data = _make_findings(
            _confirmed_finding(final_status="confirmed_blocked"),
        )
        result = convert_validated_to_agent_format(data)
        assert len(result) == 0


class TestSkipsUnlikelyVerdict:
    def test_skips_unlikely_verdict(self):
        data = _make_findings(
            _confirmed_finding(feasibility={"verdict": "unlikely"}),
        )
        result = convert_validated_to_agent_format(data)
        assert len(result) == 0


class TestIncludesConfirmedFinding:
    def test_includes_confirmed_finding(self):
        data = _make_findings(_confirmed_finding())
        result = convert_validated_to_agent_format(data)
        assert len(result) == 1
        assert result[0]["finding_id"] == "FIND-0001"
        assert result[0]["rule_id"] == "sql_injection"


class TestFieldMapping:
    def test_field_mapping(self):
        finding = _confirmed_finding(
            id="FIND-0099",
            vuln_type="xss",
            file="web.py",
            line=77,
        )
        data = _make_findings(finding)
        result = convert_validated_to_agent_format(data)
        r = result[0]
        assert r["finding_id"] == "FIND-0099"
        assert r["rule_id"] == "xss"
        assert r["file"] == "web.py"
        assert r["startLine"] == 77
        assert r["endLine"] == 77


class TestFeasibilityPassthrough:
    def test_feasibility_passthrough(self):
        feas = {
            "status": "analyzed",
            "verdict": "difficult",
            "chain_breaks": ["WAF"],
            "what_would_help": ["encoding bypass"],
            "attack_path_ref": "attack-paths.json#PATH-001",
        }
        data = _make_findings(_confirmed_finding(feasibility=feas))
        result = convert_validated_to_agent_format(data)
        # Dataclass expansion adds default fields; check the input fields are preserved
        for key, val in feas.items():
            assert result[0]["feasibility"][key] == val
        assert result[0]["attack_path_ref"] == "attack-paths.json#PATH-001"


class TestProofAsString:
    def test_proof_as_string(self):
        """proof field as string (from SARIF conversion) extracts into vulnerable_code."""
        data = _make_findings(_confirmed_finding(proof="some raw text"))
        result = convert_validated_to_agent_format(data)
        assert result[0]["snippet"] == "some raw text"


class TestMissingOptionalFields:
    def test_missing_optional_fields(self):
        """Finding with no proof/ruling/feasibility doesn't crash."""
        minimal = {
            "id": "FIND-BARE",
            "file": "x.py",
            "line": 1,
            "vuln_type": "other",
            "status": "confirmed",
        }
        data = _make_findings(minimal)
        result = convert_validated_to_agent_format(data)
        assert len(result) == 1
        assert result[0]["finding_id"] == "FIND-BARE"
        # Dataclass defaults: feasibility is a full dict with default fields, ruling likewise
        assert result[0]["feasibility"]["status"] == "pending"
        assert result[0]["ruling"]["status"] == ""
        assert result[0]["final_status"] == "pending"  # None defaults to "pending"


class TestNormalizationBeforeFiltering:
    def test_normalization_before_filtering(self):
        """convert_validated_to_agent_format self-normalizes, so RULED_OUT is filtered directly."""
        data = _make_findings(
            _confirmed_finding(status="RULED_OUT"),
            _confirmed_finding(id="FIND-0002", status="confirmed"),
        )
        result = convert_validated_to_agent_format(data)
        assert len(result) == 1
        assert result[0]["finding_id"] == "FIND-0002"

    def test_self_normalization_unlikely_verdict(self):
        """ALL_CAPS verdict 'UNLIKELY' is normalized and filtered without external normalize call."""
        data = _make_findings(
            _confirmed_finding(feasibility={"verdict": "UNLIKELY"}),
            _confirmed_finding(id="FIND-0002"),
        )
        result = convert_validated_to_agent_format(data)
        assert len(result) == 1
        assert result[0]["finding_id"] == "FIND-0002"


class TestSkipsDisproven:
    def test_skips_disproven(self):
        """Disproven findings (PoC proved not exploitable) are excluded."""
        data = _make_findings(
            _confirmed_finding(status="disproven"),
            _confirmed_finding(id="FIND-0002", status="confirmed"),
        )
        result = convert_validated_to_agent_format(data)
        assert len(result) == 1
        assert result[0]["finding_id"] == "FIND-0002"

    def test_skips_disproven_normalized(self):
        """ALL_CAPS DISPROVEN is normalized and filtered."""
        data = _make_findings(
            _confirmed_finding(status="DISPROVEN"),
            _confirmed_finding(id="FIND-0002"),
        )
        result = convert_validated_to_agent_format(data)
        assert len(result) == 1
        assert result[0]["finding_id"] == "FIND-0002"


class TestRuleIdPreference:
    def test_sarif_rule_id_preferred(self):
        """SARIF findings with original rule_id should use it instead of vuln_type."""
        finding = _confirmed_finding(
            id="SARIF-0001",
            vuln_type="sql_injection",
            rule_id="java/sql-injection",
        )
        data = _make_findings(finding)
        result = convert_validated_to_agent_format(data)
        assert result[0]["rule_id"] == "java/sql-injection"

    def test_fallback_to_vuln_type(self):
        """Findings without rule_id fall back to vuln_type."""
        data = _make_findings(_confirmed_finding(vuln_type="xss"))
        result = convert_validated_to_agent_format(data)
        assert result[0]["rule_id"] == "xss"

    def test_proof_dict_snippet_extraction(self):
        """proof as dict with vulnerable_code extracts snippet correctly."""
        finding = _confirmed_finding(
            proof={"vulnerable_code": "os.system(user_input)", "flow": ["a", "b"]},
        )
        data = _make_findings(finding)
        result = convert_validated_to_agent_format(data)
        assert result[0]["snippet"] == "os.system(user_input)"
        assert result[0]["has_dataflow"] is True
