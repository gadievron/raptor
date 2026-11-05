"""A negative result on one function does not prove its neighbours' contracts."""

import copy

import pytest

from core.audit import orchestrator as orch
from core.audit.propagation import propagate_confidence
from core.audit.refutation_source import capture_source_identity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome


@pytest.fixture
def refuted_callee(tmp_path):
    (tmp_path / "record.c").write_text("int decode_record(int n) { return n + 1; }\n")
    claim = "integer overflow in addition"
    callee = orch.ReviewOutcome(
        file="record.c", function="decode_record", line=1, status="clean", body="Reviewed.",
        hypothesis=claim, hypotheses=[{"mechanism": claim, "confidence": "high"}],
    )
    callee.claim_refutations = (ClaimRefutation(
        callee.file, callee.function, callee.line, claim,
        (ProbeOutcome("smt", "refuted", "bounded-addition"),),
        capture_source_identity(tmp_path, callee.file),
    ),)
    callee.verification_tier = callee.compute_tier(target_path=tmp_path)
    assert callee.verification_tier == "tool_backed"
    return callee


@pytest.mark.parametrize("mechanism", [
    "decode_record() could return NULL and the caller dereferences it",
    "decode_record() could return negative value",
    "assumes decode_record() always validates the supplied length",
])
def test_real_negative_receipt_does_not_prove_another_contract(refuted_callee, mechanism):
    callee = refuted_callee
    caller = orch.ReviewOutcome(
        file="consumer.c", function="consume", status="suspicious", body="Needs checking.",
        hypothesis=mechanism, hypotheses=[{"mechanism": mechanism, "confidence": "high"}],
    )
    before = copy.deepcopy(caller)
    edges = {"consumer.c:consume": [{"callee_file": callee.file, "callee": callee.function}]}
    assert propagate_confidence([callee, caller], edges) == []
    assert caller == before
    assert callee.status == "clean"


@pytest.mark.parametrize("tier", ["tool_backed", "confirmed"])
@pytest.mark.parametrize("min_callers", [1, 2, 10])
def test_clean_callers_do_not_prove_argument_safety(tier, min_callers):
    callers = [orch.ReviewOutcome(
        file="callers.c", function=f"caller_{i}", status="clean", body="Reviewed.",
        verification_tier=tier,
    ) for i in range(10)]
    target = orch.ReviewOutcome(
        file="target.c", function="decode", status="suspicious", body="Needs checking.",
        hypotheses=[{"mechanism": "caller passes invalid length"}],
    )
    edges = {f"callers.c:{caller.function}": [{
        "caller_file": caller.file, "caller": caller.function,
        "callee_file": target.file, "callee": target.function,
    }] for caller in callers}
    assert propagate_confidence(callers + [target], edges, min_callers=min_callers) == []
    assert target.status == "suspicious"
    assert target.clean_basis == ""


def test_contract_mention_cannot_clear_unrelated_claims(refuted_callee):
    target = orch.ReviewOutcome(
        file="consumer.c", function="consume", status="suspicious", body="Two concerns.",
        hypotheses=[{"mechanism": "decode_record() could return NULL"},
                    {"mechanism": "consumer releases a record twice"}],
    )
    original = copy.deepcopy(target.hypotheses)
    edges = {"consumer.c:consume": [{"callee_file": refuted_callee.file, "callee": refuted_callee.function}]}
    assert propagate_confidence([refuted_callee, target], edges, max_iterations=10) == []
    assert target.status == "suspicious"
    assert target.hypotheses == original


def test_stale_tier_does_not_authorize_contract_demotion(refuted_callee, tmp_path):
    (tmp_path / refuted_callee.file).unlink()
    target = orch.ReviewOutcome(
        file="consumer.c", function="consume", status="suspicious", body="Needs checking.",
        hypotheses=[{"mechanism": "decode_record() could return NULL"}],
    )
    assert refuted_callee.verification_tier == "tool_backed"  # Previously computed label.
    edges = {"consumer.c:consume": [{"callee_file": refuted_callee.file, "callee": refuted_callee.function}]}
    assert propagate_confidence([refuted_callee, target], edges) == []
    assert target.status == "suspicious"


def test_direct_refutation_of_target_claim_still_resolves_clean(refuted_callee, tmp_path):
    outcome = refuted_callee
    outcome.status = "suspicious"
    outcome.body = "[gate violation: G2 missing confirmation]\n\nReviewed."
    result = orch.OrchestratorResult(outcomes=[outcome], suspicious=1)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    orch._resolve_gate_demoted(result, config)
    assert result.outcomes[0].status == "clean"
    assert result.clean == 1
    assert result.suspicious == 0
