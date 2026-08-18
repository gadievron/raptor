"""Tests for core.audit.findings_export."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from core.audit.findings_export import (
    build_graded_finding,
    export_findings,
    format_findings_summary,
    write_graded_findings,
)


@dataclass
class FakeOutcome:
    file: str = "src/auth.c"
    function: str = "check_pw"
    line: int = 42
    status: str = "finding"
    hypothesis: str = "buffer overflow"
    evidence_tool: str = ""
    cost_usd: float = 0.01
    model: str = "test-model"
    review_result: dict[str, Any] | None = None


@dataclass
class FakeEvidenceRecord:
    file: str = "src/auth.c"
    function: str = "check_pw"
    sink_unreachable: bool = False
    taint_approx: Any | None = None
    taint_summary: Any | None = None
    joern_flows: list[Any] = field(default_factory=list)
    imported_joern_flows: list[Any] = field(default_factory=list)
    joern_unguarded_sinks: list[Any] = field(default_factory=list)
    codeql_alerts: list[Any] = field(default_factory=list)
    semgrep_hits: list[Any] = field(default_factory=list)
    negative_space: list[Any] = field(default_factory=list)
    binary_sink_edges: list[Any] = field(default_factory=list)


class TestBuildGradedFinding:
    def test_basic_finding(self):
        outcome = FakeOutcome(
            review_result={"hypothesis": "overflow"},
        )
        finding = build_graded_finding(outcome)
        assert finding["file"] == "src/auth.c"
        assert finding["function"] == "check_pw"
        assert finding["status"] == "finding"
        assert finding["confidence"] in ("high", "medium", "low")
        assert isinstance(finding["evidence_chain"], list)

    def test_with_evidence_record(self):
        """Ambient mechanical signals stay in the chain as context but
        an LLM-only guess no longer exports as confidence=high just
        because the function happens to have a Joern flow."""
        outcome = FakeOutcome(
            review_result={"hypothesis": "overflow"},
        )
        ev = FakeEvidenceRecord(
            joern_flows=[{"flow": 1}],
        )
        finding = build_graded_finding(outcome, ev)
        chain = finding["evidence_chain"]
        sources = {e["source"] for e in chain}
        assert "mechanical:joern" in sources
        assert finding["confidence"] != "high"

    def test_tool_receipt_keeps_high_confidence(self):
        """A genuine tool receipt (correlation-gated before stamping)
        still exports the full-chain confidence."""
        outcome = FakeOutcome(
            evidence_tool="semgrep:rule-1",
            review_result={"hypothesis": "overflow"},
        )
        ev = FakeEvidenceRecord(
            joern_flows=[{"flow": 1}],
        )
        finding = build_graded_finding(outcome, ev)
        assert finding["confidence"] == "high"

    def test_verification_tier_exported(self):
        from core.audit.orchestrator import ReviewOutcome
        outcome = ReviewOutcome(
            file="src/auth.c", function="check_pw", status="finding",
            body="", hypothesis="overflow",
            evidence_tool="semgrep:rule-1", line=3,
        )
        outcome.tools_dispatched = {"semgrep"}
        finding = build_graded_finding(outcome)
        assert finding["verification_tier"] == "tool_backed"

    def test_verification_tier_defaults_speculative(self):
        outcome = FakeOutcome(review_result={"hypothesis": "overflow"})
        finding = build_graded_finding(outcome)
        assert finding["verification_tier"] == "speculative"

    def test_dark_finding_flagged_needs_validation(self):
        outcome = FakeOutcome(
            status="dark",
            review_result={"hypothesis": "auth bypass in role check"},
        )
        finding = build_graded_finding(outcome)
        assert finding["status"] == "dark"
        assert finding["needs_validation"] is True

    def test_non_dark_finding_not_flagged(self):
        outcome = FakeOutcome(
            status="finding",
            review_result={"hypothesis": "overflow"},
        )
        finding = build_graded_finding(outcome)
        assert "needs_validation" not in finding

    def test_cwe_class_carried(self):
        outcome = FakeOutcome(
            review_result={"cwe_class": "CWE-120"},
        )
        finding = build_graded_finding(outcome)
        assert finding["cwe_class"] == "CWE-120"

    def test_impact_carried(self):
        outcome = FakeOutcome(
            review_result={
                "impact": {
                    "primitive": "write",
                    "preconditions": ["network access"],
                    "mitigations": ["ASLR"],
                },
            },
        )
        finding = build_graded_finding(outcome)
        assert finding["impact"]["primitive"] == "write"

    def test_spec_deviation_carried(self):
        outcome = FakeOutcome(
            review_result={
                "spec_deviation": {
                    "deviation": "missing bounds check",
                    "expected": "check len",
                    "actual": "no check",
                },
            },
        )
        finding = build_graded_finding(outcome)
        assert "spec_deviation" in finding

    def test_typestate_carried(self):
        outcome = FakeOutcome(
            review_result={
                "typestate_violation": {
                    "violation_kind": "double_free",
                    "type_name": "malloc/free",
                    "confirmed": True,
                },
            },
        )
        finding = build_graded_finding(outcome)
        assert finding["typestate_violation"]["violation_kind"] == "double_free"

    def test_dynamic_evidence_tool(self):
        outcome = FakeOutcome(
            evidence_tool="dynamic:sanitizer",
            review_result={"hypothesis": "crash"},
        )
        finding = build_graded_finding(outcome)
        chain = finding["evidence_chain"]
        sources = {e["source"] for e in chain}
        assert "dynamic:sanitizer" in sources

    def test_no_review_result(self):
        outcome = FakeOutcome(review_result=None)
        finding = build_graded_finding(outcome)
        assert finding["confidence"] == "low"
        assert finding["evidence_chain"] == []


class TestExportFindings:
    def test_filters_to_findings_suspicious_and_dark(self):
        """dark is the 'needs concrete verification' bucket — it must
        reach the export (and through it, operators and /validate)."""
        outcomes = [
            FakeOutcome(status="finding", review_result={"hypothesis": "a"}),
            FakeOutcome(status="clean", review_result={}),
            FakeOutcome(status="suspicious", review_result={"hypothesis": "b"}),
            FakeOutcome(status="dark", review_result={"hypothesis": "c"}),
            FakeOutcome(status="dormant", review_result={}),
            FakeOutcome(status="error", review_result={}),
        ]
        export = export_findings(outcomes)
        assert export["stats"]["total"] == 3
        assert export["stats"]["dark"] == 1
        dark = [f for f in export["findings"] if f["status"] == "dark"]
        assert len(dark) == 1
        assert dark[0]["needs_validation"] is True

    def test_stats_by_confidence(self):
        outcomes = [
            FakeOutcome(
                status="finding",
                evidence_tool="semgrep:rule-1",
                review_result={"hypothesis": "a"},
            ),
        ]
        ev_index = {
            "src/auth.c:check_pw": FakeEvidenceRecord(
                joern_flows=[{"flow": 1}],
            ),
        }
        export = export_findings(outcomes, evidence_index=ev_index)
        assert export["stats"]["high_confidence"] == 1

    def test_attack_chains_included(self):
        outcomes = [
            FakeOutcome(status="finding", review_result={"hypothesis": "a"}),
        ]
        chains = [{"chain_id": "C-1", "chain_status": "confirmed"}]
        export = export_findings(outcomes, attack_chains=chains)
        assert len(export["attack_chains"]) == 1

    def test_empty_outcomes(self):
        export = export_findings([])
        assert export["stats"]["total"] == 0
        assert export["findings"] == []


class TestWriteGradedFindings:
    def test_writes_json(self, tmp_path):
        export = {
            "findings": [{"file": "a.c", "confidence": "high"}],
            "stats": {"total": 1},
        }
        path = write_graded_findings(export, tmp_path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["stats"]["total"] == 1

    def test_creates_directory(self, tmp_path):
        subdir = tmp_path / "nested" / "dir"
        export = {"findings": [], "stats": {"total": 0}}
        path = write_graded_findings(export, subdir)
        assert path.exists()


class TestFormatFindingsSummary:
    def test_no_findings(self):
        export = {"findings": [], "stats": {"total": 0}}
        assert format_findings_summary(export) == "No findings."

    def test_with_findings(self):
        export = {
            "findings": [],
            "stats": {
                "total": 5,
                "high_confidence": 2,
                "medium_confidence": 2,
                "low_confidence": 1,
            },
        }
        text = format_findings_summary(export)
        assert "5 findings" in text
        assert "2 high-confidence" in text

    def test_with_chains(self):
        export = {
            "findings": [],
            "stats": {"total": 3, "high_confidence": 0, "medium_confidence": 0, "low_confidence": 3},
            "attack_chains": [
                {"chain_status": "confirmed"},
                {"chain_status": "hypothetical"},
            ],
        }
        text = format_findings_summary(export)
        assert "Attack chains: 2" in text
        assert "1 confirmed" in text

    def test_dark_surfaced_in_summary(self):
        export = {
            "findings": [],
            "stats": {
                "total": 4,
                "high_confidence": 1,
                "medium_confidence": 1,
                "low_confidence": 2,
                "dark": 2,
            },
        }
        text = format_findings_summary(export)
        assert "Dark" in text
        assert "/validate" in text
