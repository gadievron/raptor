"""Tests for core.audit.validate_bridge."""

from __future__ import annotations

import json

from core.audit.validate_bridge import (
    BridgeResult,
    format_bridge_summary,
    import_audit_evidence,
    import_validate_evidence,
)


def _write_manifest(d, target):
    """Write a .raptor-run.json manifest."""
    (d / ".raptor-run.json").write_text(json.dumps({"target": str(target)}))


def _write_validate_findings(d, *, with_feasibility=True):
    """Write a findings.json with optional feasibility data."""
    findings = [{
        "id": "FIND-001",
        "function": "parse_header",
        "file": "src/http.c",
        "evidence_chain": [
            {
                "source": "frida_observation",
                "tier": "OBSERVED_RUNTIME",
                "detail": "called with len=4096",
            }
        ],
    }]
    if with_feasibility:
        findings[0]["feasibility"] = {
            "verdict": "likely_exploitable",
            "chain_breaks": [],
        }
        findings[0]["final_status"] = "exploitable"

    data = {"findings": findings}
    (d / "findings.json").write_text(json.dumps(data))


def _write_audit_findings(d, target):
    """Write audit output with layer0 and taint evidence."""
    _write_manifest(d, target)

    layer0 = {
        "findings": [
            {"pattern_id": "format_string", "function": "log_msg"},
        ]
    }
    (d / "layer0-findings.json").write_text(json.dumps(layer0))

    findings = {
        "findings": [{
            "id": "FIND-001",
            "function": "parse_header",
            "file": "src/http.c",
            "evidence_chain": [
                {
                    "source": "joern_taint",
                    "detail": "taint flow found",
                },
            ],
        }]
    }
    (d / "findings.json").write_text(json.dumps(findings))


class TestBridgeResult:
    def test_empty(self):
        r = BridgeResult()
        assert not r.has_content

    def test_with_verdicts(self):
        r = BridgeResult(feasibility_verdicts=[{"verdict": "likely"}])
        assert r.has_content

    def test_to_dict(self):
        r = BridgeResult(
            source_dir="/tmp/out",
            source_command="validate",
            feasibility_verdicts=[{"v": 1}],
        )
        d = r.to_dict()
        assert d["imported"]["feasibility_verdicts"] == 1


class TestImportValidateEvidence:
    def test_colocated(self, tmp_path):
        _write_validate_findings(tmp_path)
        result = import_validate_evidence(
            tmp_path, tmp_path / "target",
        )
        assert result.has_content
        assert len(result.feasibility_verdicts) == 1
        assert result.feasibility_verdicts[0]["verdict"] == "likely_exploitable"

    def test_runtime_evidence(self, tmp_path):
        _write_validate_findings(tmp_path)
        result = import_validate_evidence(tmp_path, tmp_path / "target")
        assert len(result.runtime_evidence) == 1
        assert result.runtime_evidence[0]["tier"] == "OBSERVED_RUNTIME"

    def test_no_feasibility_skipped(self, tmp_path):
        _write_validate_findings(tmp_path, with_feasibility=False)
        result = import_validate_evidence(tmp_path, tmp_path / "target")
        assert not result.has_content

    def test_project_sibling(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()

        project_dir = tmp_path / "project"
        project_dir.mkdir()

        sibling = project_dir / "exploitability-validation-20260710"
        sibling.mkdir()
        _write_manifest(sibling, target)
        _write_validate_findings(sibling)

        audit_dir = project_dir / "audit_20260711"
        audit_dir.mkdir()

        result = import_validate_evidence(
            audit_dir, target, project_dir=project_dir,
        )
        assert result.has_content
        assert "sibling" in result.source_command

    def test_no_match(self, tmp_path):
        result = import_validate_evidence(
            tmp_path, tmp_path / "target",
        )
        assert not result.has_content


class TestImportAuditEvidence:
    def test_project_sibling(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()

        project_dir = tmp_path / "project"
        project_dir.mkdir()

        audit = project_dir / "audit_20260710"
        audit.mkdir()
        _write_audit_findings(audit, target)

        validate_dir = project_dir / "validate_20260711"
        validate_dir.mkdir()

        result = import_audit_evidence(
            validate_dir, target, project_dir=project_dir,
        )
        assert result.has_content
        assert len(result.layer0_findings) == 1
        assert len(result.taint_flows) == 1

    def test_no_match(self, tmp_path):
        result = import_audit_evidence(
            tmp_path, tmp_path / "target",
        )
        assert not result.has_content


class TestFormatSummary:
    def test_empty(self):
        r = BridgeResult()
        assert "no sibling" in format_bridge_summary(r)

    def test_with_content(self):
        r = BridgeResult(
            source_command="validate (project sibling)",
            feasibility_verdicts=[{"v": 1}, {"v": 2}],
            runtime_evidence=[{"e": 1}],
        )
        s = format_bridge_summary(r)
        assert "2 feasibility" in s
        assert "1 runtime" in s
        assert "project sibling" in s
