"""Counters and premise records belong to a mechanism, not a whole function."""

from types import SimpleNamespace

import pytest

from core.audit import orchestrator as orch
from core.audit.claim_verification import ClaimVerification

LOCAL = "Read discards the conversion error"
OTHER = "Read may race with concurrent writers"
COUNTER = "A shared lock serializes all access to the record."
STRONG = "semgrep:explicit-error-discard"
WEAK = "smt:check-early-release"


def case(tmp_path, *, claim=LOCAL, entries=(), store="review"):
    (tmp_path / "record.c").write_text("int Read(int n) { return n + 1; }\n")
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    outcome = orch.ReviewOutcome(
        file="record.c", function="Read", line=1, status="suspicious",
        body="Completed review.", hypothesis=claim,
        review_result={"hypothesis": claim, "cwe_class": "CWE-252"},
    )
    if store in ("outcome", "both"):
        outcome.hypotheses = list(entries)
    if store in ("review", "both"):
        outcome.review_result["hypotheses"] = list(entries)
    result = orch.OrchestratorResult(outcomes=[outcome], suspicious=1)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out)
    return outcome, result, config


def run_ihv(outcome, result, config, claims):
    return orch._aggregate_ihv_verdicts(
        outcome, result, [claim.hypothesis for claim in claims], claims, config,
    )


@pytest.mark.parametrize("store", ["review", "outcome", "both"])
def test_unrelated_counter_cannot_fence_selected_claim(tmp_path, store):
    entry = {"mechanism": OTHER, "confidence": "high", "counter": COUNTER}
    outcome, _, _ = case(tmp_path, entries=[entry], store=store)
    assert not orch._has_refuting_counter(outcome)
    assert orch._primary_hypothesis_entry(outcome, LOCAL) == {}


@pytest.mark.parametrize("store", ["review", "outcome", "both"])
def test_matching_counter_keeps_its_gate(tmp_path, store):
    entry = {"mechanism": LOCAL, "confidence": "high", "counter": COUNTER}
    outcome, _, _ = case(tmp_path, entries=[entry], store=store)
    assert orch._has_refuting_counter(outcome)
    assert orch._primary_hypothesis_entry(outcome, LOCAL) == entry


@pytest.mark.parametrize("other", [
    LOCAL + " on shutdown", LOCAL[:-5], LOCAL.upper(),
    "X" * 120 + " second operation",
])
def test_prefix_case_and_long_common_prefix_do_not_bind_counters(tmp_path, other):
    selected = "X" * 120 + " first operation" if other.startswith("X") else LOCAL
    entry = {"mechanism": other, "confidence": "high", "counter": COUNTER}
    outcome, _, _ = case(tmp_path, claim=selected, entries=[entry])
    assert not orch._has_refuting_counter(outcome)
    assert orch._primary_hypothesis_entry(outcome, selected) == {}


def test_exact_record_wins_over_unrelated_high_confidence_entry(tmp_path):
    exact = {"mechanism": LOCAL, "confidence": "low"}
    outcome, _, _ = case(tmp_path, entries=[
        {"mechanism": OTHER, "confidence": "high", "counter": COUNTER}, exact,
    ])
    assert orch._primary_hypothesis_entry(outcome, LOCAL) is exact
    assert not orch._has_refuting_counter(outcome)


def test_outer_whitespace_does_not_lose_matching_counter(tmp_path):
    outcome, _, _ = case(tmp_path, entries=[
        {"mechanism": "  " + LOCAL + "\n", "counter": COUNTER},
    ])
    assert orch._has_refuting_counter(outcome)


@pytest.mark.parametrize("status", ["clean", "suspicious"])
def test_ihv_secondary_confirmation_is_not_vetoed_by_primary_counter(tmp_path, status):
    primary = {"mechanism": OTHER, "confidence": "high", "counter": COUNTER}
    secondary = {"mechanism": LOCAL, "confidence": "high", "cwe": "CWE-252"}
    outcome, result, config = case(tmp_path, claim=OTHER, entries=[primary, secondary], store="both")
    outcome.status = status
    final = run_ihv(outcome, result, config, [
        ClaimVerification(primary, (WEAK,)), ClaimVerification(secondary, (STRONG,)),
    ])
    assert final.status == "finding"
    assert final.hypothesis == final.review_result["hypothesis"] == LOCAL
    assert final.evidence_tool == STRONG
    assert final.review_result["immediate_verified"]
    assert result.immediate_verified == 1
    assert outcome.hypothesis == OTHER  # Candidate selection preserves the original review.


def test_ihv_counter_from_selected_record_is_not_lost_without_review_copy(tmp_path):
    outcome, result, config = case(tmp_path)
    selected = {"mechanism": LOCAL, "confidence": "high", "counter": COUNTER, "counter_scope": "local"}
    final = run_ihv(outcome, result, config, [ClaimVerification(selected, (STRONG,))])
    assert final.status == "suspicious"
    assert final.review_result["ihv_gate_blocked"] == "refuting-counter"
    assert not final.review_result.get("immediate_verified")
    assert result.immediate_verified == 0


def test_ihv_can_continue_after_its_first_supported_claim_is_countered(tmp_path):
    primary = {"mechanism": OTHER, "confidence": "high", "counter": COUNTER, "counter_scope": "local"}
    secondary = {"mechanism": LOCAL, "confidence": "high"}
    outcome, result, config = case(tmp_path, claim=OTHER, entries=[primary, secondary])
    final = run_ihv(outcome, result, config, [
        ClaimVerification(primary, (STRONG,)), ClaimVerification(secondary, (STRONG,)),
    ])
    assert final.status == "finding"
    assert final.hypothesis == LOCAL
    assert "ihv_gate_blocked" not in final.review_result


def test_ihv_selected_record_does_not_inherit_a_stale_counter_copy(tmp_path):
    outcome, result, config = case(tmp_path, entries=[
        {"mechanism": LOCAL, "confidence": "high", "counter": COUNTER},
    ])
    final = run_ihv(outcome, result, config, [ClaimVerification({"mechanism": LOCAL}, (STRONG,))])
    assert final.status == "finding"


@pytest.mark.parametrize("counter", [None, 7, [], "safe", "no plausible defect here"])
def test_absent_malformed_or_dismissive_counter_does_not_fence(tmp_path, counter):
    outcome, _, _ = case(tmp_path, entries=[{"mechanism": LOCAL, "counter": counter}])
    assert not orch._has_refuting_counter(outcome)


@pytest.mark.parametrize("entry", [None, "counter", {}, {"mechanism": None}, {"mechanism": 7}])
def test_unidentifiable_hypothesis_cannot_supply_a_counter(tmp_path, entry):
    outcome, _, _ = case(tmp_path, entries=[entry])
    assert not orch._has_refuting_counter(outcome)
    assert orch._primary_hypothesis_entry(outcome, LOCAL) == {}


def patch_chain(monkeypatch, seen):
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *args, **kwargs: [{"type": "semgrep"}])
    monkeypatch.setattr(orch, "run_prefilter", lambda **kwargs: SimpleNamespace(hits=[]))
    def run(chain, **kwargs):
        seen.append(kwargs["hypothesis"])
        return [STRONG]
    monkeypatch.setattr(orch, "_run_tool_chain", run)


@pytest.mark.parametrize("matching", [False, True])
def test_legacy_promotion_uses_the_counter_for_its_selected_primary(tmp_path, monkeypatch, matching):
    entry = {"mechanism": LOCAL if matching else OTHER, "confidence": "high", "counter": COUNTER}
    outcome, result, config = case(tmp_path, entries=[entry])
    # The legacy lane takes its primary from review_result, which can differ
    # from the previous outcome's primary after a review update.
    outcome.hypothesis = OTHER
    seen = []
    patch_chain(monkeypatch, seen)
    orch._promote_suspicious_one(result, config, 0, outcome, checklist={})
    assert seen == ([] if matching else [LOCAL])
    assert result.outcomes[0].status == ("suspicious" if matching else "finding")
    if not matching:
        assert result.outcomes[0].hypothesis == LOCAL
        assert result.outcomes[0].review_result["hypothesis"] == LOCAL
        assert result.outcomes[0].evidence_tool == STRONG
        assert outcome.hypothesis == OTHER
        assert "evidence_tool" not in outcome.review_result


@pytest.mark.parametrize("matching", [False, True])
def test_zero_dispatch_supply_is_not_fenced_by_another_claim(tmp_path, monkeypatch, matching):
    entry = {"mechanism": LOCAL if matching else OTHER, "confidence": "high", "counter": COUNTER}
    outcome, result, config = case(tmp_path, entries=[entry])
    outcome.hypothesis = OTHER
    seen = []
    patch_chain(monkeypatch, seen)
    orch._resweep_zero_dispatch_suspicious(result, config)
    assert seen == ([] if matching else [LOCAL])
    assert result.outcomes[0].status == "suspicious"  # Supply is not promotion.


def test_exact_review_counter_is_found_despite_unrelated_outcome_entries(tmp_path):
    entry = {"mechanism": LOCAL, "confidence": "medium", "counter": COUNTER}
    outcome, _, _ = case(tmp_path, entries=[entry])
    outcome.hypotheses = [{"mechanism": OTHER, "confidence": "high"}]
    assert orch._primary_hypothesis_entry(outcome, LOCAL) is entry
    assert orch._has_refuting_counter(outcome)


def test_missing_selected_identity_cannot_borrow_highest_confidence_counter(tmp_path):
    outcome, _, _ = case(tmp_path, claim="", entries=[
        {"mechanism": OTHER, "confidence": "high", "counter": COUNTER},
    ])
    assert not orch._has_refuting_counter(outcome)
    assert orch._primary_hypothesis_entry(outcome, "") == {}


@pytest.mark.parametrize("matching", [False, True])
def test_finding_validation_binds_external_premise_to_the_checked_mechanism(tmp_path, monkeypatch, matching):
    entry = {"mechanism": LOCAL if matching else OTHER, "confidence": "high",
             "counter": COUNTER, "counter_scope": "cross_function"}
    outcome, _, config = case(tmp_path, entries=[entry])
    outcome.status = "finding"
    seen = []
    notes = []
    patch_chain(monkeypatch, seen)
    monkeypatch.setattr(orch, "_note_premise_blocked_validation", lambda *args, **kwargs: notes.append(args[1]))
    final = orch._sweep_validate(outcome, config)
    assert seen == [LOCAL]
    assert bool(final.evidence_tool) is not matching
    assert notes == ([entry] if matching else [])
