"""Weak signals sharing a premise cannot manufacture verification authority."""

from itertools import combinations
from types import SimpleNamespace

import pytest

from core.audit import orchestrator as orch
from core.audit.claim_verification import ClaimVerification
from core.audit.evidence_grade import is_tool_evidence, is_verification_evidence

WEAK = (
    "smt:check-early-release", "codeql-llm:dataflow", "joern:live",
    "consistency:return-check-majority", "fail_open:handler-outcome-naming",
    "dark_verify:confirmed",
)
STRONG = "semgrep:explicit-error-discard"
CLAIM = "Read discards the conversion error"


@pytest.mark.parametrize("receipts", list(combinations(WEAK, 2)) + [WEAK, WEAK * 3])
def test_namespace_count_never_grants_verification(receipts):
    stamp = "+".join(receipts)
    assert not is_tool_evidence(stamp)
    assert not is_verification_evidence(stamp)
    assert not orch._promotion_grade_receipt(stamp)
    assert orch._aggregate_channel_confirmations(list(receipts)) == ([], 0.0)


@pytest.mark.parametrize("receipts", [(STRONG, *WEAK), (*WEAK, STRONG)])
def test_real_verification_receipt_remains_authoritative(receipts):
    assert is_tool_evidence("+".join(receipts))
    assert is_verification_evidence("+".join(receipts))


def case(tmp_path, *, status="suspicious"):
    (tmp_path / "record.c").write_text("int Read(int n) { return n; }\n")
    outcome = orch.ReviewOutcome(
        file="record.c", function="Read", line=1, status=status, body="Reviewed.",
        hypothesis=CLAIM, review_result={"hypothesis": CLAIM, "cwe_class": "CWE-252"},
    )
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    config.out_dir.mkdir()
    result = orch.OrchestratorResult(outcomes=[outcome], suspicious=int(status == "suspicious"))
    return outcome, config, result


@pytest.mark.parametrize("status", ["clean", "suspicious"])
@pytest.mark.parametrize("receipts", [WEAK[:2], WEAK[:3], WEAK])
def test_ihv_keeps_shared_premise_leads_unverified(tmp_path, status, receipts):
    outcome, config, result = case(tmp_path, status=status)
    claim = {"mechanism": CLAIM, "confidence": "high", "premise": "model-generated contract"}
    final = orch._aggregate_ihv_verdicts(outcome, result, [claim], [ClaimVerification(claim, receipts)], config)
    assert final.status == status
    assert final.review_result["ihv_tools"] == list(receipts)
    assert not final.review_result.get("immediate_verified")
    assert result.immediate_verified == 0
    assert "aggregated_promotion" not in final.review_result


@pytest.mark.parametrize("status", ["clean", "suspicious"])
def test_ihv_selects_real_proof_ahead_of_all_shared_leads(tmp_path, status):
    outcome, config, result = case(tmp_path, status=status)
    claim = {"mechanism": CLAIM, "cwe": "CWE-252"}
    final = orch._aggregate_ihv_verdicts(outcome, result, [claim], [ClaimVerification(claim, (*WEAK, STRONG))], config)
    assert final.status == "finding"
    assert final.hypothesis == CLAIM
    assert final.evidence_tool == STRONG
    assert result.immediate_verified == 1


def patch_chain(monkeypatch, receipts):
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *args, **kwargs: [{"type": "smt"}])
    monkeypatch.setattr(orch, "_run_tool_chain", lambda *args, **kwargs: list(receipts))
    monkeypatch.setattr(orch, "run_prefilter", lambda **kwargs: SimpleNamespace(hits=[]))


@pytest.mark.parametrize("lane", ["validate", "promote"])
@pytest.mark.parametrize("strong", [False, True])
def test_legacy_lanes_require_a_real_verification_receipt(tmp_path, monkeypatch, lane, strong):
    outcome, config, result = case(tmp_path, status="finding" if lane == "validate" else "suspicious")
    patch_chain(monkeypatch, (*WEAK, STRONG) if strong else WEAK)
    if lane == "validate":
        final = orch._sweep_validate(outcome, config)
        assert final.evidence_tool == (STRONG if strong else "")
    else:
        orch._promote_suspicious_one(result, config, 0, outcome)
        final = result.outcomes[0]
        assert final.status == ("finding" if strong else "suspicious")
        assert result.aggregation_promoted == 0
    assert "aggregated_promotion" not in final.review_result


@pytest.mark.parametrize("stamp,dispatched", [
    ("+".join(WEAK), set()),
    ("llm-claimed:smt:check-early-release", {"smt"}),
    ("llm-claimed:smt+semgrep:explicit-error-discard", {"smt", "semgrep"}),
])
def test_re_review_floor_cannot_restore_weak_or_claimed_authority(tmp_path, stamp, dispatched):
    outcome, _, _ = case(tmp_path)
    outcome.evidence_tool = stamp
    outcome.tools_dispatched = dispatched
    assert not orch._probe_backed_suspicious(outcome)


def test_re_review_floor_still_preserves_verified_receipt(tmp_path):
    outcome, _, _ = case(tmp_path)
    outcome.evidence_tool = STRONG + "+llm-claimed:smt"
    assert orch._probe_backed_suspicious(outcome)


def test_historical_posterior_metadata_cannot_restore_authority(tmp_path):
    outcome, _, _ = case(tmp_path, status="finding")
    outcome.evidence_tool = "+".join(WEAK)
    outcome.review_result["aggregated_promotion"] = {
        "channels": ["smt", "codeql-llm", "joern"], "posterior_mean": 0.999,
        "threshold": 0.7, "receipts": list(WEAK),
    }
    assert outcome.compute_tier() == "llm_only"
    assert any(gate.startswith("G2") for gate in orch._check_finding_gates(outcome))
