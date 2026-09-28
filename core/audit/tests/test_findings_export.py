"""Tests for core.audit.findings_export."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from core.audit.evidence_grade import sanitize_llm_evidence_tool
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
    typestate_violations: list[Any] = field(default_factory=list)


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

    def test_fabricated_typestate_claim_not_high_confidence(self):
        """A model-authored ``typestate_violation.confirmed`` with no
        pipeline-injected typestate context must not export
        confidence=high on an llm_only finding, and must not earn a
        ``mechanical:`` namespace item at HIGH."""
        outcome = FakeOutcome(
            review_result={
                "hypothesis": "double free of conn",
                "typestate_violation": {
                    "violation_kind": "double_free",
                    "type_name": "malloc/free",
                    "confirmed": True,
                },
            },
        )
        finding = build_graded_finding(outcome)
        assert finding["confidence"] != "high"
        for e in finding["evidence_chain"]:
            assert not (
                e["source"].startswith("mechanical:")
                and e["confidence"] == "high"
            )

    def test_typestate_claim_with_injected_context_caps_at_medium(self):
        """With genuine pipeline typestate context for the function,
        the model's confirmation grades LLM-corroborated (medium) —
        never the mechanical HIGH tier."""
        from types import SimpleNamespace

        outcome = FakeOutcome(
            review_result={
                "hypothesis": "double free of conn",
                "typestate_violation": {
                    "violation_kind": "double_free",
                    "type_name": "malloc/free",
                    "confirmed": True,
                },
            },
        )
        ev = FakeEvidenceRecord(
            typestate_violations=[SimpleNamespace(
                type_name="malloc/free", violation_kind="double_free",
            )],
        )
        finding = build_graded_finding(outcome, ev)
        assert finding["confidence"] == "medium"
        sources = {e["source"] for e in finding["evidence_chain"]}
        assert "llm:corroborated" in sources

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

class TestCallerEvidenceClamp:
    _RECORD = {
        "rule_id": "api_boundary:caller-contract",
        "outcome": "refuted",
        "contract": "callers must not invoke again on the same b "
                    "(single-call contract)",
        "reason": "all 2 in-repo call site(s) honour the contract",
        "sites": [],
        "enumeration": {"method": "tree-scan", "complete": True,
                        "notes": []},
        "demotion": {"confidence_clamp": "low", "status": "suspicious"},
    }

    def test_caller_evidence_exported_and_confidence_clamped(self):
        outcome = FakeOutcome(
            status="suspicious",
            review_result={
                "hypothesis": "double free if a caller invokes it twice",
                "caller_evidence": dict(self._RECORD),
            },
        )
        finding = build_graded_finding(outcome)
        assert finding["caller_evidence"]["outcome"] == "refuted"
        assert finding["confidence"] == "low"

    def test_confirming_receipt_blocks_the_clamp(self):
        # Tool-confirmed findings are never demoted: a confirming-role
        # receipt outranks the caller-contract refutation.
        outcome = FakeOutcome(
            evidence_tool="semgrep:rule-1",
            review_result={
                "hypothesis": "double free if a caller invokes it twice",
                "caller_evidence": dict(self._RECORD),
            },
        )
        finding = build_graded_finding(outcome)
        assert finding["caller_evidence"]  # record still travels
        assert finding["confidence"] != "low"

    def test_record_without_demotion_does_not_clamp(self):
        record = dict(self._RECORD, demotion=None)
        outcome = FakeOutcome(
            evidence_tool="smt:check-null-propagation",
            review_result={
                "hypothesis": "double free if a caller invokes it twice",
                "caller_evidence": record,
            },
        )
        finding = build_graded_finding(outcome)
        assert finding["caller_evidence"]
        # No clamp requested — confidence derives from the chain alone.
        assert finding["confidence"] in ("high", "medium", "low")


class TestGadgetAbsenceClamp:
    _RECORD = {
        "rule_id": "gadget_oracle:no-gadget-surface",
        "outcome": "refuted",
        "reason": "no-gadget-surface-complete-census",
        "absence_tier": "no_gadget_surface",
        "census": {"complete": True, "php_files": 4},
        "qualifier": "census complete",
        "demotion": {"confidence_clamp": "low", "status": "suspicious"},
    }
    _HYP = "object injection gadget chain via unserialize"

    def test_gadget_absence_exported_and_confidence_clamped(self):
        outcome = FakeOutcome(
            status="suspicious",
            review_result={
                "hypothesis": self._HYP,
                "gadget_absence": dict(self._RECORD),
            },
        )
        finding = build_graded_finding(outcome)
        assert finding["gadget_absence"]["outcome"] == "refuted"
        assert finding["confidence"] == "low"
        # The clamp demotes confidence only — status is untouched.
        assert finding["status"] == "suspicious"

    def test_confirming_receipt_blocks_the_clamp(self):
        # Tool-confirmed findings are never demoted: a confirming-role
        # receipt outranks the absence refutation.
        outcome = FakeOutcome(
            evidence_tool="semgrep:rule-1",
            review_result={
                "hypothesis": self._HYP,
                "gadget_absence": dict(self._RECORD),
            },
        )
        finding = build_graded_finding(outcome)
        assert finding["gadget_absence"]  # record still travels
        assert finding["confidence"] != "low"

    def test_record_without_demotion_does_not_clamp(self):
        record = dict(self._RECORD, demotion=None)
        outcome = FakeOutcome(
            evidence_tool="smt:check-null-propagation",
            review_result={
                "hypothesis": self._HYP,
                "gadget_absence": record,
            },
        )
        finding = build_graded_finding(outcome)
        assert finding["gadget_absence"]
        # No clamp requested — confidence derives from the chain alone.
        assert finding["confidence"] in ("high", "medium", "low")


class TestConfirmedByDiscrimination:
    """Incident regression (openssh instrumented corpus):
    ``discovery.confirmed_by`` read a never-set outcome attribute and
    exported ``[]`` on 185/185 findings while ``verification_tier``
    claimed tool_backed on 137 of them — 136 were disproven in
    validation. confirmed_by is now derived from confirming-role
    receipts, and tool_backed with no confirming receipt is capped."""

    def test_confirmed_by_derived_from_confirming_receipt(self):
        outcome = FakeOutcome(
            evidence_tool="semgrep:rule-1",
            review_result={"hypothesis": "overflow"},
        )
        finding = build_graded_finding(outcome)
        assert finding["discovery"]["confirmed_by"] == ["semgrep:rule-1"]

    def test_detection_stamp_stays_out_of_confirmed_by(self):
        outcome = FakeOutcome(
            evidence_tool="smt:check-toctou",
            review_result={"hypothesis": "toctou"},
        )
        finding = build_graded_finding(outcome)
        assert finding["discovery"]["confirmed_by"] == []

    def test_secondary_confirmation_lands_in_confirmed_by(self):
        outcome = FakeOutcome(
            evidence_tool="smt:check-toctou",
            review_result={
                "hypothesis": "toctou",
                "secondary_confirmations": [
                    {"mechanism": "m", "evidence_tool": "coccinelle:r1"},
                    # premise-blocked confirmations do not confirm
                    {"mechanism": "b", "evidence_tool": "smt",
                     "premise_blocked": True},
                ],
            },
        )
        finding = build_graded_finding(outcome)
        assert finding["discovery"]["confirmed_by"] == ["coccinelle:r1"]

    def test_tool_backed_with_empty_confirmed_by_is_capped(self):
        # Journaled-attribute path: the recorded tier says tool_backed
        # but no receipt qualifies — the export must not ship the claim.
        outcome = FakeOutcome(
            evidence_tool="smt:check-toctou",
            review_result={"hypothesis": "toctou"},
        )
        outcome.verification_tier = "tool_backed"
        finding = build_graded_finding(outcome)
        assert finding["verification_tier"] == "llm_only"
        assert finding["confidence"] != "high"

    def test_tool_backed_with_confirming_receipt_survives(self):
        outcome = FakeOutcome(
            evidence_tool="semgrep:rule-1",
            review_result={"hypothesis": "overflow"},
        )
        outcome.verification_tier = "tool_backed"
        finding = build_graded_finding(outcome)
        assert finding["verification_tier"] == "tool_backed"
        assert finding["discovery"]["confirmed_by"] == ["semgrep:rule-1"]

    def test_llm_claimed_witness_part_stays_out_of_confirmed_by(self):
        # sanitize_llm_evidence_tool prefixes the model's whole raw
        # string, so a claim ending ":witness" reaches this derivation
        # (the journal keep-and-sanitize re-export shape). It must not
        # ride the witness arm into confirmed_by and defeat the
        # no-receipt tier cap.
        outcome = FakeOutcome(
            evidence_tool="llm-claimed:smt:check-toctou:witness",
            review_result={"hypothesis": "toctou"},
        )
        outcome.verification_tier = "tool_backed"
        finding = build_graded_finding(outcome)
        assert finding["discovery"]["confirmed_by"] == []
        assert finding["verification_tier"] == "llm_only"
        assert finding["confidence"] != "high"

    def test_genuine_witness_stamp_still_confirms(self):
        # Other direction: an unprefixed pipeline witness receipt (a
        # concrete solver model discriminates) keeps its confirming
        # role and the recorded tier.
        outcome = FakeOutcome(
            evidence_tool="smt:check-toctou:witness",
            review_result={"hypothesis": "toctou"},
        )
        outcome.verification_tier = "tool_backed"
        finding = build_graded_finding(outcome)
        assert finding["discovery"]["confirmed_by"] \
            == ["smt:check-toctou:witness"]
        assert finding["verification_tier"] == "tool_backed"

    def test_part_after_claim_marker_stays_out_of_confirmed_by(self):
        # sanitize_llm_evidence_tool prefixes the model's WHOLE raw
        # string, so a '+' inside the claim splits into tail parts that
        # no longer carry the prefix — every part after the marker is
        # the claim's own text (the is_verification_evidence positional
        # rule). A receipt-shaped tail must not land in confirmed_by
        # and defeat the no-receipt tier cap.
        stamp = sanitize_llm_evidence_tool(
            "consistency:cross-check agrees+smt:check-integer-narrowing",
        )
        outcome = FakeOutcome(
            evidence_tool=stamp,
            review_result={"hypothesis": "integer narrowing"},
        )
        outcome.verification_tier = "tool_backed"
        finding = build_graded_finding(outcome)
        assert finding["discovery"]["confirmed_by"] == []
        assert finding["verification_tier"] == "llm_only"
        assert finding["confidence"] != "high"

    def test_receipt_before_claim_marker_still_confirms(self):
        # Other direction: the evidence-combine shape puts the genuine
        # receipt FIRST and the sanitized claim after it — parts before
        # the marker keep their confirming role and the recorded tier.
        outcome = FakeOutcome(
            evidence_tool="smt:check-integer-narrowing+llm-claimed:smt",
            review_result={"hypothesis": "integer narrowing"},
        )
        outcome.verification_tier = "tool_backed"
        finding = build_graded_finding(outcome)
        assert finding["discovery"]["confirmed_by"] \
            == ["smt:check-integer-narrowing"]
        assert finding["verification_tier"] == "tool_backed"


class TestConfirmedHistoryReceipt:
    """A reviewed outcome matching a fresh CONFIRMED /validate history
    entry gains validate:confirmed-history — incident: selected()'s
    validate-confirmed dead branch exported speculative with
    confirmed_by=[]."""

    def _record(self, confirmed):
        rec = FakeEvidenceRecord()
        for c in confirmed:
            c.setdefault("strong_receipts", True)
        rec.validate_history = {"confirmed": confirmed, "ruled_out": []}
        return rec

    def _outcome(self, **kw):
        kw.setdefault("line", 234)
        kw.setdefault("status", "finding")
        kw.setdefault(
            "hypothesis",
            "uid < 0 comparison on unsigned uid_t is a dead branch",
        )
        kw.setdefault(
            "review_result", {"hypothesis": "dead branch", "cwe_class": "CWE-697"},
        )
        return FakeOutcome(**kw)

    def test_line_and_cwe_match_stamps_receipt(self):
        rec = self._record([{
            "fresh": True, "line": 242, "cwe": "cwe-697",
        }])
        finding = build_graded_finding(self._outcome(), rec)
        assert "validate:confirmed-history" in finding["discovery"]["confirmed_by"]

    def test_line_match_cwe_conflict_needs_mechanism_overlap(self):
        # The incident shape: /validate said CWE-570, the review said
        # CWE-697 — same dead-branch mechanism, noisy CWE labels.
        rec = self._record([{
            "fresh": True, "line": 242, "cwe": "CWE-570",
            "mechanism": "unsigned uid < 0 is provably always false",
        }])
        finding = build_graded_finding(self._outcome(), rec)
        assert "validate:confirmed-history" in finding["discovery"]["confirmed_by"]

    def test_line_match_cwe_conflict_no_overlap_never_convicts(self):
        rec = self._record([{
            "fresh": True, "line": 242, "cwe": "CWE-120",
            "mechanism": "memcpy destination smaller than source length",
        }])
        finding = build_graded_finding(self._outcome(), rec)
        assert "validate:confirmed-history" not in finding["discovery"]["confirmed_by"]

    def test_receipt_survives_tool_backed_gate(self):
        outcome = self._outcome()
        outcome.verification_tier = "tool_backed"
        rec = self._record([{"fresh": True, "line": 242, "cwe": "cwe-697"}])
        finding = build_graded_finding(outcome, rec)
        # Pre-fix: confirmed_by=[] demoted this to llm_only.
        assert finding["verification_tier"] == "tool_backed"

    def test_same_cwe_far_line_never_convicts(self):
        # A confirmed defect of the same CWE hundreds of lines away is
        # a different mechanism — disagreeing lines veto.
        rec = self._record([{
            "fresh": True, "line": 900, "cwe": "cwe-697",
            "mechanism": "uid < 0 unsigned comparison dead branch",
        }])
        finding = build_graded_finding(self._outcome(), rec)
        assert "validate:confirmed-history" not in finding["discovery"]["confirmed_by"]

    def test_cwe_match_without_lines_needs_mechanism_overlap(self):
        rec = self._record([{
            "fresh": True, "line": 0, "cwe": "cwe-697",
            "mechanism": "uid < 0 unsigned comparison dead branch",
        }])
        finding = build_graded_finding(self._outcome(), rec)
        assert "validate:confirmed-history" in finding["discovery"]["confirmed_by"]

    def test_cwe_match_without_lines_no_overlap_never_convicts(self):
        rec = self._record([{
            "fresh": True, "line": 0, "cwe": "cwe-697",
            "mechanism": "pointer comparison against freed sentinel",
        }])
        finding = build_graded_finding(self._outcome(), rec)
        assert "validate:confirmed-history" not in finding["discovery"]["confirmed_by"]

    def test_stale_confirm_never_convicts(self):
        rec = self._record([{"fresh": False, "line": 242, "cwe": "cwe-697"}])
        finding = build_graded_finding(self._outcome(), rec)
        assert "validate:confirmed-history" not in finding["discovery"]["confirmed_by"]

    def test_bare_status_flip_never_convicts(self):
        # A ruling with no strong receipts and no runtime tiers is a
        # bare opinion — it must not defeat the discrimination gate.
        rec = self._record([])
        rec.validate_history = {"confirmed": [{
            "fresh": True, "line": 242, "cwe": "cwe-697",
            "strong_receipts": False, "runtime_tiers": [],
        }], "ruled_out": []}
        finding = build_graded_finding(self._outcome(), rec)
        assert "validate:confirmed-history" not in finding["discovery"]["confirmed_by"]

    def test_function_level_overlap_alone_never_convicts(self):
        rec = self._record([{"fresh": True, "line": 900, "cwe": "CWE-120"}])
        finding = build_graded_finding(self._outcome(), rec)
        assert "validate:confirmed-history" not in finding["discovery"]["confirmed_by"]

    def test_non_finding_status_never_convicts(self):
        rec = self._record([{"fresh": True, "line": 242, "cwe": "cwe-697"}])
        finding = build_graded_finding(self._outcome(status="ruled_out"), rec)
        assert "validate:confirmed-history" not in finding["discovery"]["confirmed_by"]

    def test_malformed_line_tolerated(self):
        rec = self._record([{
            "fresh": True, "line": "~242", "cwe": "cwe-697",
            "mechanism": "uid < 0 unsigned comparison dead branch",
        }])
        # Treated as line-unknown: falls to the CWE+mechanism rule.
        finding = build_graded_finding(self._outcome(), rec)
        assert "validate:confirmed-history" in finding["discovery"]["confirmed_by"]
