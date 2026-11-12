"""Basis records retain exact historical attribution and no proof authority."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from core.audit.assessment_basis import read_assessment_basis, record_assessment_basis
from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.refutation_source import SourceIdentity
from core.audit.review_claims import begin_review, merge_history


ORIGIN = KnowledgeOrigin("fixture-pass", "owned.c", "f", 1, 3,
                         SourceIdentity("a" * 64, (1, 2, 40, 4, 5)))


def _record():
    return record_assessment_basis(begin_review(ORIGIN, "fixture-attempt"),
        origin=ORIGIN, attempt_id="fixture-attempt", status="clean")


def test_model_basis_binds_existing_review_and_survives_json_without_mutating_input():
    history = begin_review(ORIGIN, "fixture-attempt")
    original = deepcopy(history)
    recorded = record_assessment_basis(history, origin=ORIGIN,
        attempt_id="fixture-attempt", status="clean")
    assert history == original
    projected = read_assessment_basis(json.loads(json.dumps(recorded)), pass_id="fixture-pass", status="clean")
    assert projected["basis"] == "model_judgment"
    assert projected["attempt_id"] == "fixture-attempt"
    assert projected["origin"]["source_identity"]["sha256"] == ORIGIN.source_identity.sha256
    assert projected["scope"] == "historical_review_only"
    assert "assurance" not in projected and "verified" not in projected
    projected["origin"]["file"] = "changed.c"
    assert recorded["review"]["origin"]["file"] == "owned.c"


@pytest.mark.parametrize("change", [
    {"pass_id": "different-pass"}, {"file": "different.c"}, {"function": "other"},
    {"line_start": 2}, {"source_identity": SourceIdentity("b" * 64, (1, 2, 40, 4, 5))},
    {"source_identity": None},
])
def test_producer_cannot_stamp_a_different_or_unbound_observation(change):
    origin = replace(ORIGIN, **change)
    assert record_assessment_basis(begin_review(ORIGIN, "fixture-attempt"), origin=origin,
        attempt_id="fixture-attempt", status="clean") is None


def test_wrong_attempt_and_incomplete_producer_outcomes_stay_unavailable():
    history = begin_review(ORIGIN, "fixture-attempt")
    assert record_assessment_basis(history, origin=ORIGIN, attempt_id="other", status="clean") is None
    assert record_assessment_basis(history, origin=ORIGIN, attempt_id="fixture-attempt", status="error") is None
    assert record_assessment_basis(begin_review(replace(ORIGIN, source_identity=None), "fixture-attempt"),
        origin=replace(ORIGIN, source_identity=None), attempt_id="fixture-attempt", status="clean") is None


def test_selected_status_and_pass_cannot_borrow_historical_basis():
    recorded = _record()
    assert read_assessment_basis(recorded, pass_id="another-pass", status="clean") is None
    assert read_assessment_basis(recorded, pass_id="fixture-pass", status="finding") is None


def test_decision_boolean_or_legacy_top_label_does_not_issue_basis():
    history = begin_review(ORIGIN, "fixture-attempt")
    history["assessment_basis"] = "model_judgment_withdrawal"
    history["withdrawal_decisions"] = {"admissible": True, "accepted": [{"adjudication": "model_withdrawn"}]}
    assert read_assessment_basis(history, pass_id="fixture-pass", status="clean") is None


def test_explicit_producer_stamp_retains_recorded_withdrawal_as_judgment_only():
    history = _record()
    # This label is written by the existing withdrawal producer only after
    # admission; no admission is established by this pure unit control.
    history["assessment_basis"] = "model_judgment_withdrawal"
    history["withdrawal_decisions"] = {"admissible": True}
    assert read_assessment_basis(history, pass_id="fixture-pass", status="clean") is None
    recorded = record_assessment_basis(history, origin=ORIGIN, attempt_id="fixture-attempt", status="clean",
                                        basis="model_judgment_withdrawal")
    projected = read_assessment_basis(recorded, pass_id="fixture-pass", status="clean")
    assert projected["basis"] == "model_judgment_withdrawal"
    assert projected["scope"] == "historical_review_only"
    assert record_assessment_basis(recorded, origin=ORIGIN, attempt_id="fixture-attempt", status="clean") is None


def test_mixed_contributors_and_unmapped_merged_history_do_not_select_a_basis():
    recorded = _record()
    other = begin_review(replace(ORIGIN, pass_id="second-pass"), "second-attempt")
    assert read_assessment_basis(merge_history(recorded, other), pass_id="fixture-pass", status="clean") is None
    recorded["intakes"].append({"claims": [], "review": other["review"]})
    assert read_assessment_basis(recorded, pass_id="fixture-pass", status="clean") is None


@pytest.mark.parametrize("field,value", [
    ("assessment_basis", "mechanically_verified"), ("assessment_status", "error"),
    ("origin", {"pass_id": "fixture-pass"}), ("attempt_id", ""),
])
def test_malformed_or_unknown_recorded_basis_is_unavailable(field, value):
    history = _record()
    history["review"][field] = value
    assert read_assessment_basis(history, pass_id="fixture-pass", status="clean") is None


def test_malformed_existing_top_label_is_not_repaired_by_stamping():
    history = begin_review(ORIGIN, "fixture-attempt")
    history["assessment_basis"] = {"admissible": True}
    assert record_assessment_basis(history, origin=ORIGIN,
        attempt_id="fixture-attempt", status="clean") is None


def test_same_binding_with_conflicting_contributor_basis_is_unavailable():
    recorded = _record()
    contributor = deepcopy(recorded["review"])
    contributor["assessment_basis"] = "model_judgment_withdrawal"
    recorded["intakes"].append({"claims": [], "review": contributor})
    assert read_assessment_basis(recorded, pass_id="fixture-pass", status="clean") is None


def test_recorded_terminal_status_is_not_silently_rewritten():
    recorded = _record()
    assert record_assessment_basis(recorded, origin=ORIGIN,
        attempt_id="fixture-attempt", status="suspicious") is None
    assert record_assessment_basis(recorded, origin=ORIGIN,
        attempt_id="fixture-attempt", status="clean") == recorded


@pytest.mark.parametrize("field,value", [("assessment_basis", "mechanically_verified"),
                                         ("assessment_status", None)])
def test_stamping_does_not_repair_corrupt_nested_basis(field, value):
    recorded = _record()
    recorded["review"][field] = value
    assert record_assessment_basis(recorded, origin=ORIGIN,
        attempt_id="fixture-attempt", status="clean") is None


@pytest.mark.parametrize("target", ["origin", "source_identity"])
def test_unknown_scope_fields_cannot_be_promoted_to_public_basis(target):
    recorded = _record()
    value = recorded["review"]["origin"]
    if target == "source_identity":
        value = value["source_identity"]
    value["build_closure"] = {"assurance": "mechanically_verified"}
    assert read_assessment_basis(recorded, pass_id="fixture-pass", status="clean") is None
