"""A clean verification tier needs scoped negative evidence, not dispatch."""

from dataclasses import replace

import pytest

from core.audit import orchestrator as orch
from core.audit.refutation_source import capture_source_identity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome

CLAIM = "integer overflow in addition"
SECOND = "early release of the allocated record"


@pytest.fixture
def clean_case(tmp_path):
    (tmp_path / "record.c").write_text("int Read(int n) { return n + 1; }\n")
    outcome = orch.ReviewOutcome(
        file="record.c", function="Read", line=1, status="clean", body="Reviewed.",
        hypothesis=CLAIM, hypotheses=[{"mechanism": CLAIM, "confidence": "high"}],
        tools_dispatched={"smt"},
    )
    receipt = ClaimRefutation(
        outcome.file, outcome.function, outcome.line, CLAIM,
        (ProbeOutcome("smt", "refuted", "bounded-addition"),),
        capture_source_identity(tmp_path, outcome.file),
    )
    return outcome, receipt


def test_dispatch_without_refutation_cannot_grade_clean_tool_backed(clean_case, tmp_path):
    outcome, _ = clean_case
    assert outcome.compute_tier(target_path=tmp_path) == "speculative"


def test_matching_current_refutation_can_grade_clean_tool_backed(clean_case, tmp_path):
    outcome, receipt = clean_case
    outcome.claim_refutations = (receipt,)
    outcome.tools_dispatched.clear()
    assert outcome.compute_tier(target_path=tmp_path) == "tool_backed"


def test_current_target_is_required_even_with_a_receipt(clean_case):
    outcome, receipt = clean_case
    outcome.claim_refutations = (receipt,)
    assert outcome.compute_tier() == "speculative"


@pytest.mark.parametrize("field,value", [
    ("file", "other.c"), ("function", "Other"), ("line_start", 2),
    ("hypothesis", SECOND), ("source_identity", None),
    ("checks", (ProbeOutcome("smt", "inconclusive", "bounded-addition"),)),
])
def test_unmatched_negative_cannot_raise_clean_tier(clean_case, tmp_path, field, value):
    outcome, receipt = clean_case
    outcome.claim_refutations = (replace(receipt, **{field: value}),)
    assert outcome.compute_tier(target_path=tmp_path) == "speculative"


@pytest.mark.parametrize("change", ["edited", "deleted", "replaced"])
def test_source_drift_invalidates_negative_tier(clean_case, tmp_path, change):
    outcome, receipt = clean_case
    outcome.claim_refutations = (receipt,)
    file = tmp_path / outcome.file
    if change == "edited":
        file.write_text("int Read(int n) { return n + 2; }\n")
    elif change == "deleted":
        file.unlink()
    else:
        replacement = tmp_path / "replacement.c"
        replacement.write_bytes(file.read_bytes())
        replacement.replace(file)
    assert outcome.compute_tier(target_path=tmp_path) == "speculative"


@pytest.mark.parametrize("complete", [False, True])
def test_all_active_claims_require_their_own_refutations(clean_case, tmp_path, complete):
    outcome, receipt = clean_case
    outcome.hypotheses.append({"mechanism": SECOND, "confidence": "high"})
    outcome.claim_refutations = (receipt,)
    if complete:
        outcome.claim_refutations += (replace(receipt, hypothesis=SECOND),)
    assert outcome.compute_tier(target_path=tmp_path) == ("tool_backed" if complete else "speculative")


@pytest.mark.parametrize("basis", ["gate_resolved", "propagated", "sarif_clean", "unknown"])
def test_nonreusable_clean_basis_cannot_gain_tier_from_refutation(clean_case, tmp_path, basis):
    outcome, receipt = clean_case
    outcome.claim_refutations = (receipt,)
    outcome.clean_basis = basis
    assert outcome.compute_tier(target_path=tmp_path) == "speculative"


def test_model_dictionary_cannot_supply_negative_authority(clean_case, tmp_path):
    outcome, receipt = clean_case
    outcome.claim_refutations = (receipt.to_record(),)
    outcome.review_result = {"immediate_verified": True, "ihv_all_refuted": True}
    assert outcome.compute_tier(target_path=tmp_path) == "speculative"


def test_commit_supplies_target_for_clean_tier(clean_case, tmp_path, monkeypatch):
    outcome, receipt = clean_case
    outcome.claim_refutations = (receipt,)
    out = tmp_path / "out"
    out.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out)
    monkeypatch.setattr("core.audit.collector.append_journal_for_outcome", lambda **kwargs: None)
    orch._commit_outcome(config, outcome, {"file": outcome.file, "name": outcome.function, "line_start": 1})
    assert outcome.verification_tier == "tool_backed"


def test_collector_supplies_target_for_clean_tier(clean_case, tmp_path):
    from core.audit.collector import Collector

    outcome, receipt = clean_case
    outcome.claim_refutations = (receipt,)
    out = tmp_path / "out"
    out.mkdir()
    collector = Collector(out_dir=out, target_path=tmp_path)
    collector.submit(outcome, {"file": outcome.file, "name": outcome.function, "line_start": 1})
    assert outcome.verification_tier == "tool_backed"
