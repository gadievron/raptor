"""Exact historical comparison inputs never become claim authority."""
from copy import deepcopy
from dataclasses import asdict

import pytest

from core.audit.claims import ClaimRevision
from core.audit.findings_export import build_graded_finding
from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.orchestrator import ReviewOutcome
from core.audit.refutation_source import capture_source_identity
from core.audit.review_claims import begin_review, record_intake


@pytest.fixture
def history_case(tmp_path):
    (tmp_path / "unit.c").write_text("int Read(void) { return 0; }\n")
    source = capture_source_identity(tmp_path, "unit.c")
    hypothesis = {"mechanism": "the returned value is unchecked", "confidence": "low"}
    revision = ClaimRevision(hypothesis, pass_id="intake-pass", file="unit.c", function="Read", line_start=1)
    origin = KnowledgeOrigin("review-pass", "unit.c", "Read", 1, 1, source)
    history = record_intake(begin_review(origin, "review-attempt"), [revision])
    outcome = ReviewOutcome("unit.c", "Read", "suspicious", "reviewed fixture", line=1,
                            hypothesis=hypothesis["mechanism"], hypotheses=[deepcopy(hypothesis)],
                            review_result={"review_claims": history})
    return outcome, revision, history


def test_actual_export_retains_exact_historical_claim_identity(history_case):
    outcome, revision, _ = history_case
    before = asdict(outcome)
    finding = build_graded_finding(outcome)
    link = finding["verification_trace"].get("claim_lineage", {})
    assert link.get("claim_reference") == revision.event_reference()
    assert link["review_pass_id"] == "review-pass"
    assert link["intake_pass_id"] == "intake-pass"
    assert link["authoritative"] is False and link["source_revalidated_at_export"] is False
    assert asdict(outcome) == before


@pytest.mark.parametrize("change", ["statement", "location", "merged", "omission", "count", "conflict", "ambiguous", "bad_id"])
def test_history_cannot_supply_an_ambiguous_or_changed_final_claim(history_case, change):
    from core.audit.claim_comparison_inputs import historical_claim_link

    outcome, revision, history = history_case
    finding = build_graded_finding(outcome)
    value = deepcopy(history)
    if change == "statement":
        finding["hypothesis"] = "a different concern"
    elif change == "location":
        finding["line"] = 2
    elif change == "merged":
        value["review"] = None
        value["complete"] = False
        value["omissions"] = ["merged-candidate-projection-unmapped"]
    elif change == "omission":
        value["intakes"][0]["omitted_count"] = 1
    elif change == "count":
        value["intakes"][0]["candidate_count"] += 1
    elif change == "bad_id":
        value["intakes"][0]["claims"][0]["reference"]["revision_id"] = "model-supplied"
    else:
        extra = deepcopy(value["intakes"][0]["claims"][0])
        if change == "conflict":
            # This conflicting definition would disappear if final-claim
            # filtering happened before quarantine.
            extra["hypothesis"]["mechanism"] = "other statement"
        else:
            other = ClaimRevision(revision.hypothesis, pass_id="other-intake", file="unit.c", function="Read", line_start=1)
            extra["reference"] = other.reference()
        value["intakes"][0]["claims"].append(extra)
        value["intakes"][0]["candidate_count"] += 1
    before = deepcopy(value)
    link = historical_claim_link(value, finding)
    assert link["status"] == "unavailable" and "claim_reference" not in link
    assert value == before
    if change == "conflict":
        assert link["reason"] == "invalid_or_conflicting_history"
    if change == "ambiguous":
        assert link["reason"] == "ambiguous_final_claim"


def test_duplicate_history_does_not_create_another_identity(history_case):
    from core.audit.claim_comparison_inputs import historical_claim_link

    outcome, _, history = history_case
    finding = build_graded_finding(outcome)
    expected = historical_claim_link(history, finding)
    history["intakes"][0]["claims"].append(deepcopy(history["intakes"][0]["claims"][0]))
    history["intakes"][0]["candidate_count"] += 1
    assert historical_claim_link(history, finding) == expected


def test_historical_link_does_not_claim_current_source_or_copy_context(history_case, tmp_path):
    from core.audit.claim_comparison_inputs import historical_claim_link
    from core.json import dumps_canonical

    outcome, _, history = history_case
    sentinel = "PRIVATE_SOURCE_CONTEXT_MUST_NOT_BE_COPIED"
    history["reference_inputs"] = {"question": sentinel}
    (tmp_path / "unit.c").write_text("changed after the review\n")
    link = historical_claim_link(history, build_graded_finding(outcome))
    assert link["status"] == "recorded" and link["source_revalidated_at_export"] is False
    assert sentinel not in dumps_canonical(link)
    assert outcome.status == "suspicious"
