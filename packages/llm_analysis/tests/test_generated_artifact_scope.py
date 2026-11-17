"""Generated-program observations must not acquire target authority."""

from pathlib import Path

import pytest

from core.labeled_attempts.view import OutcomeStatus, from_witness
from core.witness import WitnessOutcome, WitnessSource, WitnessStore
from packages.llm_analysis import crash_agent
from packages.llm_analysis.exploit_verify import _grade_executed_outcome
from packages.llm_analysis.verification_tier import (
    derive_verification_tier,
    mechanical_receipt,
)
from packages.llm_analysis.witness_adapter import witness_from_exploit
from packages.zkpox.eligibility import is_zkpox_eligible


@pytest.mark.parametrize("body", [None, "", " \n\t"])
@pytest.mark.parametrize("builder", [
    crash_agent._crash_analysis_system_prompt,
    crash_agent._crash_exploit_system_prompt,
])
def test_missing_persona_refuses_prompt_construction(monkeypatch, body, builder):
    monkeypatch.setattr(crash_agent, "load_methodology", lambda name: body)
    with pytest.raises(RuntimeError, match="Required crash persona"):
        builder()


@pytest.mark.parametrize("name,builder", [
    ("crash_analyst.md", crash_agent._crash_analysis_system_prompt),
    ("binary_exploitation_specialist.md", crash_agent._crash_exploit_system_prompt),
])
def test_standalone_persona_is_required_in_runtime_prompt(monkeypatch, name, builder):
    root = Path(__file__).resolve().parents[3]
    body = (root / "tiers" / "personas" / name).read_text()
    monkeypatch.setattr(crash_agent, "load_methodology", lambda requested: body)
    assert body in builder()
    assert "unable to verify" in body.lower()
    assert "actual" in body.lower() and "target" in body.lower()
    assert "hypothesis" in body.lower()


@pytest.mark.parametrize("outcome", [
    WitnessOutcome.EXIT_SIGNAL,
    WitnessOutcome.SANITIZER_REPORT,
    WitnessOutcome.FLAG_CAPTURED,
])
def test_target_hash_and_authenticated_record_do_not_bind_generated_code(tmp_path, outcome):
    target = tmp_path / "declared-target"
    target.write_bytes(b"an authorized artifact which was never executed")
    witness, data = witness_from_exploit(
        "int main(void) { return 0; }", finding_id="F",
        target_binary_path=target, executed_outcome=outcome,
        executed_detail={"target_verification": "verified", "evidence_grade": "mechanical"},
    )
    assert witness.target_binary_hash
    assert witness.observed_outcome is WitnessOutcome.UNKNOWN
    assert witness.outcome_detail["generated_artifact_outcome"] == outcome.value
    assert witness.outcome_detail["target_verification"] == "unverified"

    # Exercise historical positive manifests too, including store authentication.
    witness.observed_outcome = outcome
    store = WitnessStore(tmp_path / "witnesses")
    store.put(witness, data)
    restored = store.get_witness(witness.bytes_hash)
    assert restored.provenance_verified
    projected = from_witness(restored)
    assert projected.status is OutcomeStatus.INCONCLUSIVE
    assert not projected.reproducible
    assert not is_zkpox_eligible(restored).eligible

    # Ordinary target-input witnesses retain their existing positive semantics.
    restored.source = WitnessSource.FUZZ
    assert from_witness(restored).status is OutcomeStatus.VERIFIED
    assert is_zkpox_eligible(restored).eligible


def test_kernel_signal_observation_is_preserved_without_target_promotion():
    detail = {"signal_num": 11}
    _grade_executed_outcome(
        WitnessOutcome.EXIT_SIGNAL, detail,
        {"status": {"exit_kind": "signaled", "termsig": 11}}, None,
    )
    assert detail["evidence_grade"] == "mechanical"
    assert detail["observation_scope"] == "generated_artifact"
    assert detail["target_verification"] == "unverified"
    finding = {
        "execute_outcome": "exit_signal", "execute_detail": detail,
        "intent_match": {"verdict": "matches"},
        "verification_tier": "confirmed", "target_verified": True,
        "target_binary_hash": "a" * 64,
    }
    assert derive_verification_tier(finding) == "llm_only"
    assert mechanical_receipt(finding, "exploitable") == ""
