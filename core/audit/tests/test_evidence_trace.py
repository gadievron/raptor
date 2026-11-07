"""Normal audit exports expose provenance without manufacturing proof."""

import json

from core.audit.findings_export import (
    build_graded_finding,
    export_findings,
    export_graded_from_journal,
    write_graded_findings,
)
from core.audit.orchestrator import ReviewOutcome
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome
from core.coverage.journal import ReviewJournalEntry, append_entry, now_iso


def test_normal_json_export_retains_channel_states_without_confirming_them(tmp_path):
    outcome = ReviewOutcome(
        file="a.c", function="f", function_qualified="Owner.f", line=12,
        status="suspicious", body="Review", hypothesis="Unresolved claim",
        tools_dispatched={"smt", "semgrep"}, tools_errored={"semgrep"},
        tools_skipped={"codeql"}, tools_inconclusive={"smt"},
    )
    write_graded_findings(export_findings([outcome]), tmp_path)
    finding = json.loads((tmp_path / "findings-graded.json").read_text())["findings"][0]
    trace = finding["verification_trace"]
    assert trace["claim"] == "Unresolved claim"
    assert trace["scope"] == {"file": "a.c", "function": "f", "function_qualified": "Owner.f", "line": 12}
    assert trace["channels"] == {"dispatched": ["semgrep", "smt"], "errored": ["semgrep"],
                                 "skipped": ["codeql"], "inconclusive": ["smt"]}
    assert trace["confirming_markers"] == []
    assert trace["claim_check_details"] == "unavailable"
    assert trace["final_status"] == finding["status"]
    assert trace["verification_tier"] == finding["verification_tier"]
    assert outcome.status == "suspicious"


def test_model_trace_and_receipts_cannot_manufacture_recorded_checks():
    outcome = ReviewOutcome(
        file="a.c", function="f", status="dark", body="Review",
        review_result={"verification_trace": {"confirming_markers": ["smt"]},
                       "claim_refutations": [{"checks": [{"verdict": "refuted"}]}]},
    )
    trace = build_graded_finding(outcome)["verification_trace"]
    assert trace["confirming_markers"] == []
    assert trace["claim_checks"] == []
    assert trace["channels"]["dispatched"] is None


def test_scoped_receipt_keeps_original_claim_and_source_identity():
    identity = SourceIdentity("a" * 64, (1, 2, 3, 4, 5))
    receipt = ClaimRefutation("a.c", "f", 12, "Earlier claim",
                              (ProbeOutcome("smt", "refuted", "smt:test", "Unsatisfiable"),), identity)
    outcome = ReviewOutcome(file="a.c", function="f", line=12, status="suspicious",
                            body="Review", hypothesis="Current claim", claim_refutations=(receipt,))
    trace = build_graded_finding(outcome)["verification_trace"]
    check = trace["claim_checks"][0]
    assert check["hypothesis"] == "Earlier claim"
    assert check["checks"][0]["verdict"] == "refuted"
    assert check["source_identity"]["sha256"] == identity.sha256
    assert check["matches_final_claim"] is False
    assert check["source_revalidated_at_export"] is False
    assert trace["claim_check_details"] == "recorded"
    assert outcome.claim_refutations == (receipt,)


def test_review_assumptions_remain_unverified():
    outcome = ReviewOutcome(file="a.c", function="f", status="suspicious", body="Review",
                            hypotheses=[{"mechanism": "Claim", "assumed_property": "Caller holds lock"},
                                        {"mechanism": "Other", "assumed_property": None}])
    trace = build_graded_finding(outcome)["verification_trace"]
    assert trace["assumptions"] == [{"hypothesis": "Claim", "property": "Caller holds lock",
                                     "origin": "review", "verified": False}]


def test_journal_reconstruction_preserves_available_states_and_marks_unknowns(tmp_path):
    append_entry(tmp_path, ReviewJournalEntry(
        ts=now_iso(), run_id=tmp_path.name, file="a.c", function="f", function_qualified="Owner.f",
        verdict="suspicious", source_hash="abc", line_start=12,
        evidence_tools=["smt:check-overflow"], tools_dispatched=["smt"], tools_skipped=["codeql"],
        hypotheses=[{"mechanism": "Claim", "assumed_property": "Input is unbounded"}],
    ))
    finding = export_graded_from_journal(tmp_path)["findings"][0]
    trace = finding["verification_trace"]
    assert trace["derivation"] == "review-journal"
    assert trace["receipt_scope"] == "run"
    assert trace["channels"] == {"dispatched": ["smt"], "skipped": ["codeql"],
                                 "errored": None, "inconclusive": None}
    assert trace["claim_check_details"] == "unavailable"
    assert trace["assumptions"][0]["verified"] is False
    assert trace["scope"]["function_qualified"] == "Owner.f"


def test_unverified_journal_cannot_export_confirming_markers(tmp_path):
    (tmp_path / "review-journal.jsonl").write_text(json.dumps({
        "ts": now_iso(), "run_id": tmp_path.name, "file": "a.c", "function": "f",
        "verdict": "suspicious", "source_hash": "", "evidence_tools": ["smt"],
    }) + "\n")
    trace = export_graded_from_journal(tmp_path)["findings"][0]["verification_trace"]
    assert trace["evidence_marker"].startswith("llm-claimed:")
    assert trace["confirming_markers"] == []
    assert trace["receipt_scope"] is None
