"""Immediate verification binds each receipt to the claim it tested."""

from types import SimpleNamespace

import pytest

from core.audit import orchestrator as orch
from core.audit.claim_verification import ClaimVerification, supported_claims


WEAK = "smt:check-early-release"
OTHER_WEAK = "codeql-llm:dataflow"
STRONG = "semgrep:explicit-error-discard"


def select(*records):
    return supported_claims(
        records, receipt_can_promote=orch._promotion_grade_receipt,
    )


@pytest.mark.parametrize("receipts", [
    (WEAK,), (OTHER_WEAK,), (WEAK, WEAK),
    ("llm-claimed:semgrep",), ("invented:proof",),
    ("invented:a", "unknown:b"), ("llm-claimed:smt", OTHER_WEAK),
])
def test_weak_or_unrecognised_evidence_cannot_confirm_a_claim(receipts):
    assert select(ClaimVerification({"mechanism": "overflow"}, receipts)) == []


def test_two_weak_receipts_cannot_corroborate_different_claims():
    assert select(
        ClaimVerification({"mechanism": "race"}, (WEAK,)),
        ClaimVerification({"mechanism": "injection"}, (OTHER_WEAK,)),
    ) == []


def test_weak_channels_cannot_confirm_even_within_a_single_claim():
    record = ClaimVerification({"mechanism": "race"}, (WEAK, OTHER_WEAK))
    assert select(record) == []


def test_strong_receipt_is_selected_ahead_of_a_weak_lead_on_the_same_claim():
    result = select(ClaimVerification({"mechanism": "discarded error"}, (WEAK, STRONG)))
    assert result[0].receipts == (STRONG,)


def aggregate(tmp_path, records, *, status="clean"):
    outcome = orch.ReviewOutcome(
        file="record.c", function="Read", status=status, body="completed review",
        hypothesis="original primary", review_result={"hypothesis": "original primary", "cwe_class": "CWE-190"},
    )
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    result = orch.OrchestratorResult()
    out = orch._aggregate_ihv_verdicts(
        outcome, result, [r.hypothesis for r in records], records, config,
    )
    return out, result, outcome


@pytest.mark.parametrize("status", ["clean", "suspicious"])
def test_detection_lead_does_not_become_a_verified_finding(tmp_path, status):
    out, result, _ = aggregate(tmp_path, [ClaimVerification({"mechanism": "race"}, (WEAK,))], status=status)
    assert out.status == status
    assert not out.review_result.get("immediate_verified")
    assert out.review_result["ihv_tools"] == [WEAK]
    assert result.immediate_verified == 0


def test_receipt_for_secondary_claim_cannot_be_exported_as_primary(tmp_path):
    records = [
        ClaimVerification({"mechanism": "unproven race", "cwe": "CWE-362"}, (WEAK,)),
        ClaimVerification({"mechanism": "discarded error", "cwe": "CWE-252"}, (STRONG,)),
    ]
    out, result, prior = aggregate(tmp_path, records)
    assert out.status == "finding"
    assert out.hypothesis == out.review_result["hypothesis"] == "discarded error"
    assert out.review_result["cwe"] == out.review_result["cwe_class"] == "CWE-252"
    assert out.evidence_tool == STRONG
    assert result.immediate_verified == 1
    assert prior.hypothesis == prior.review_result["hypothesis"] == "original primary"


def test_blocked_claim_does_not_hide_another_supported_claim(tmp_path, monkeypatch):
    seen = []

    def gate(outcome, config, **kwargs):
        seen.append(outcome.hypothesis)
        return "caller-attributed" if outcome.hypothesis == "caller bug" else None

    monkeypatch.setattr(orch, "_ihv_context_gate", gate)
    out, _, _ = aggregate(tmp_path, [
        ClaimVerification({"mechanism": "caller bug"}, (STRONG,)),
        ClaimVerification({"mechanism": "local bug"}, (STRONG,)),
    ])
    assert seen == ["caller bug", "local bug"]
    assert out.status == "finding"
    assert out.hypothesis == "local bug"
    assert "ihv_gate_blocked" not in out.review_result


def test_function_local_proof_cannot_verify_a_cross_function_premise(tmp_path, monkeypatch):
    notes = []
    monkeypatch.setattr(orch, "_note_premise_blocked_validation", lambda *a, **kw: notes.append(a[1]))
    claim = {"mechanism": "overflow", "counter_scope": "cross_function",
             "counter": "The caller clamps the length before calling."}
    out, result, _ = aggregate(tmp_path, [ClaimVerification(claim, (STRONG,))])
    assert out.status == "clean"
    assert out.review_result["ihv_gate_blocked"] == "cross-function-premise"
    assert out.hypothesis == out.review_result["hypothesis"] == "original primary"
    assert out.review_result["cwe_class"] == "CWE-190"
    assert result.immediate_verified == 0
    assert notes == [claim]


def test_extraction_preserves_the_counter_on_each_claim():
    primary = {"mechanism": "overflow", "confidence": "high", "counter_scope": "cross_function",
               "counter": "Caller bounds the input."}
    secondary = {"mechanism": "race", "confidence": "medium", "counter_scope": "local",
                 "counter": "A shared lock covers both accesses."}
    outcome = orch.ReviewOutcome(file="record.c", function="Read", status="clean", body="reviewed",
                                hypothesis="overflow", hypotheses=[primary, secondary])
    claims = orch._extract_all_hypotheses(outcome)
    assert [(h["counter"], h["counter_scope"]) for h in claims] == [
        (h["counter"], h["counter_scope"]) for h in [primary, secondary]
    ]


def test_synthesis_is_given_the_selected_claim_not_the_original_primary(tmp_path, monkeypatch):
    import core.audit.checker_synthesis as synthesis

    seen = []

    def synthesize(outcome, config, **kwargs):
        seen.append((outcome.hypothesis, dict(outcome.review_result)))
        return SimpleNamespace(confirmed=True, stamp=STRONG, cost_usd=0)

    monkeypatch.setattr(synthesis, "synthesize_verification_rule", synthesize)
    original = orch.ReviewOutcome(file="record.c", function="Read", status="clean", body="reviewed",
                                 hypothesis="original", review_result={"hypothesis": "original", "cwe_class": "CWE-190"})
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    receipt = orch._try_ihv_synthesis(original, config, orch.OrchestratorResult(),
                                    {"mechanism": "selected secondary"}, "CWE-252", "source")
    assert receipt == STRONG
    assert seen[0][0] == seen[0][1]["hypothesis"] == "selected secondary"
    assert seen[0][1]["cwe_class"] == "CWE-252"
    assert original.hypothesis == original.review_result["hypothesis"] == "original"


def test_confirmation_and_refutation_cannot_coexist_in_one_record():
    with pytest.raises(ValueError):
        ClaimVerification({"mechanism": "overflow"}, (STRONG,), refuted=True)


def test_record_snapshots_the_claim_it_verified():
    hypothesis = {"mechanism": "overflow"}
    record = ClaimVerification(hypothesis, (STRONG,))
    hypothesis["mechanism"] = "unrelated race"
    assert record.hypothesis["mechanism"] == "overflow"


def test_immediate_dispatch_keeps_secondary_receipts_bound_to_their_claim(tmp_path, monkeypatch):
    primary = {"mechanism": "unproven race", "confidence": "high", "cwe": "CWE-362"}
    secondary = {"mechanism": "discarded error", "confidence": "medium", "cwe": "CWE-252"}
    outcome = orch.ReviewOutcome(
        file="record.c", function="Read", status="clean", body="reviewed",
        hypothesis=primary["mechanism"], hypotheses=[primary, secondary],
        review_result={"hypothesis": primary["mechanism"], "cwe": primary["cwe"]},
    )
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", immediate_verify=True)
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [{"type": "semgrep"}])
    seen = []

    def run_chain(chain, **kwargs):
        seen.append(kwargs["hypothesis"])
        return [WEAK] if kwargs["hypothesis"] == primary["mechanism"] else [STRONG]

    monkeypatch.setattr(orch, "_run_tool_chain", run_chain)
    out = orch._verify_hypotheses_immediate(outcome, config, orch.OrchestratorResult())
    assert seen == [primary["mechanism"], secondary["mechanism"]]
    assert out.status == "finding"
    assert out.hypothesis == out.review_result["hypothesis"] == secondary["mechanism"]
    assert out.review_result["cwe"] == secondary["cwe"]
    assert out.evidence_tool == STRONG
