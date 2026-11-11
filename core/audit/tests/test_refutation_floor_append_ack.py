"""Real best-effort recording failures retain the existing receipt floor."""
from dataclasses import asdict
import json

import pytest

from core.analysis import reach_chokepoint
from core.audit import refutation
from core.audit.lifetime_witness import LifetimeClaimResult, LifetimeProof
from core.audit.orchestrator import OrchestratorConfig, ReviewOutcome


def _outcome():
    return ReviewOutcome("src/unit.c", "Read", "clean", "prior assessment", line=7,
                         hypotheses=[{"mechanism": "CWE-190: integer overflow — the ntohs() length wraps the 32-bit accumulator downstream",
                                      "confidence": "low", "counter": "the value is bounded by its return type"}])


def test_real_best_effort_sink_failure_retains_existing_receipt_floor(tmp_path):
    output = tmp_path / "owned-file"
    output.write_bytes(b"preserved")
    outcome = _outcome()
    before = asdict(outcome)
    config = OrchestratorConfig(tmp_path, output)
    verdict = refutation.rescue_self_refuted(outcome, config=config, pre_evidence="smt:check-parsed-int-contract")
    assert output.read_bytes() == b"preserved" and asdict(outcome) == before
    assert verdict is not None
    assert verdict.demote_to == "suspicious"


def _lifetime():
    proof = LifetimeProof("supplied", "owned", "supplied record-only fixture", frozenset({"CWE-416"}))
    return LifetimeClaimResult(True, proof.cwes, (proof,), "supplied record-only fixture")


def test_failed_native_record_append_refuses_lifetime_discharge(tmp_path):
    output = tmp_path / "owned-file"
    output.write_bytes(b"preserved")
    outcome = _outcome()
    witness = _lifetime()
    before = asdict(outcome), asdict(witness)
    assert refutation._record_lifetime_discharge(outcome, output, mechanism="fixture", result=witness) is False
    assert output.read_bytes() == b"preserved"
    assert (asdict(outcome), asdict(witness)) == before


def test_successful_append_preserves_existing_floor_resolution_and_record(tmp_path):
    outcome = _outcome()
    before = asdict(outcome)
    verdict = refutation.rescue_self_refuted(outcome, config=OrchestratorConfig(tmp_path, tmp_path),
                                           pre_evidence="smt:check-parsed-int-contract")
    assert verdict is None and asdict(outcome) == before
    rows = [json.loads(line) for line in (tmp_path / "suppressions.jsonl").read_bytes().splitlines()]
    assert len(rows) == 1 and rows[0]["verdict"] == "refuter_dominates_receipt"
    assert rows[0]["finding_id"] == "audit-refutation:src/unit.c:Read:7"
    assert rows[0]["dropped"] is False and rows[0]["refuter_grade"] == "proof"


def test_successful_lifetime_append_preserves_existing_record(tmp_path):
    assert refutation._record_lifetime_discharge(_outcome(), tmp_path,
                                                mechanism="fixture", result=_lifetime()) is True
    row = json.loads((tmp_path / "suppressions.jsonl").read_bytes())
    assert row["verdict"] == "lifetime_witness_corroborates_dismissal"
    assert row["arms"] == ["supplied"] and row["pointers"] == ["owned"]
    assert row["covered_cwes"] == ["CWE-416"] and row["dropped"] is False


def _record(kind, tmp_path):
    if kind == "lifetime":
        return refutation._record_lifetime_discharge(_outcome(), tmp_path,
                                                     mechanism="fixture", result=_lifetime())
    return refutation._record_floor_dominance(
        _outcome(), OrchestratorConfig(tmp_path, tmp_path),
        refuter=refutation.RefutationVerdict("input_bound_t0", "supplied record-only fixture", "clean", "proof"),
        receipt="existing receipt fixture", floor_gate="anti_self_refutation",
    )


@pytest.mark.parametrize("kind", ["lifetime", "floor"])
@pytest.mark.parametrize("ack", [None, False, 1, "complete"])
def test_unacknowledged_or_truthy_writer_result_refuses_override(tmp_path, monkeypatch, kind, ack):
    monkeypatch.setattr(reach_chokepoint, "record_suppression", lambda *args, **kwargs: ack)
    assert _record(kind, tmp_path) is False
    assert not (tmp_path / "suppressions.jsonl").exists()


@pytest.mark.parametrize("kind", ["lifetime", "floor"])
def test_interrupt_identity_is_preserved(tmp_path, monkeypatch, kind):
    primary = KeyboardInterrupt("owned record interrupted")

    def interrupt(*args, **kwargs):
        raise primary

    monkeypatch.setattr(reach_chokepoint, "record_suppression", interrupt)
    with pytest.raises(KeyboardInterrupt) as caught:
        _record(kind, tmp_path)
    assert caught.value is primary
