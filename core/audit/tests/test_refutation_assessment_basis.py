"""Historical serializer/consumer controls, never checker-execution proof."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from core.audit.assessment_basis import read_assessment_basis, record_assessment_basis
from core.audit.claims import ClaimRevision
from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.refutation_assessment_basis import read_refutation_basis, record_refutation_basis
from core.audit.refutation_source import SourceIdentity
from core.audit.review_claims import begin_review
from core.audit.verification_results import ClaimRefutation, ProbeOutcome


ORIGIN = KnowledgeOrigin("fixture-pass", "owned.c", "f", 1, 3,
                         SourceIdentity("a" * 64, (1, 2, 40, 4, 5)))
SUBJECT = "a bounded fixture concern"


def _receipt(subject=SUBJECT):
    # Typed admission-boundary fixture; no checker or solver was executed.
    return ClaimRefutation("owned.c", "f", 1, subject,
        (ProbeOutcome("fixture", "refuted", "fixture:scoped-negative", "Fixture conclusion"),),
        ORIGIN.source_identity)


def _history():
    return record_assessment_basis(begin_review(ORIGIN, "fixture-attempt"),
        origin=ORIGIN, attempt_id="fixture-attempt", status="clean")


def _record():
    return record_refutation_basis(_history(), origin=ORIGIN, attempt_id="fixture-attempt",
                                   hypotheses=[SUBJECT], receipts=(_receipt(),))


def test_existing_receipt_snapshot_survives_json_as_historical_basis_without_authority():
    history = _history()
    before = deepcopy(history)
    receipt = _receipt()
    recorded = record_refutation_basis(history, origin=ORIGIN, attempt_id="fixture-attempt",
                                       hypotheses=[SUBJECT], receipts=(receipt,))
    assert history == before
    expected = json.loads(json.dumps(receipt.to_record()))
    assert recorded["review"]["assessment_refutations"] == [expected]
    projected = read_assessment_basis(json.loads(json.dumps(recorded)), pass_id="fixture-pass", status="clean")
    assert projected["basis"] == "enumerated_claims_refuted"
    assert projected["scope"] == "historical_review_only"
    refutations = projected["refutations"]
    assert refutations == {"hypotheses": [SUBJECT], "records": [{
        "hypothesis": SUBJECT, "checks": [expected["checks"][0]],
    }]}
    assert "assurance" not in projected and "verified" not in projected
    refutations["hypotheses"].append("changed")
    refutations["records"][0]["checks"][0]["reason"] = "changed"
    assert recorded["review"]["assessment_hypotheses"] == [SUBJECT]
    assert recorded["review"]["assessment_refutations"][0]["checks"][0]["reason"] == "Fixture conclusion"


def test_exact_repeat_is_idempotent_but_different_same_pass_snapshot_is_not_repaired():
    recorded = _record()
    assert record_refutation_basis(recorded, origin=ORIGIN, attempt_id="fixture-attempt",
        hypotheses=[SUBJECT], receipts=(_receipt(),)) == recorded
    changed = replace(_receipt(), checks=(ProbeOutcome("fixture", "refuted", "fixture:other", "Changed"),))
    assert record_refutation_basis(recorded, origin=ORIGIN, attempt_id="fixture-attempt",
        hypotheses=[SUBJECT], receipts=(changed,)) is None


def test_original_lineage_and_rejection_context_remain_durable_without_becoming_public_authority():
    revision = ClaimRevision({"mechanism": SUBJECT}, pass_id="fixture-intake",
                             file="owned.c", function="f", line_start=1)
    receipt = replace(_receipt(), claim_revision=revision, material_admission=("CWE-120", ("fixture premise",)))
    recorded = record_refutation_basis(_history(), origin=ORIGIN, attempt_id="fixture-attempt",
                                       hypotheses=[SUBJECT], receipts=(receipt,))
    saved = recorded["review"]["assessment_refutations"][0]
    assert saved["claim_reference"] == revision.event_reference()
    assert saved["material_admission"]["role"] == "rejection_context_not_checker_scope"
    projected = read_refutation_basis(recorded["review"])
    assert "claim_reference" not in projected["records"][0]
    assert "material_admission" not in projected["records"][0]


def test_same_text_with_different_lineage_is_not_resolved_by_receipt_order():
    first = ClaimRevision({"mechanism": SUBJECT}, pass_id="fixture-first",
                          file="owned.c", function="f", line_start=1)
    second = ClaimRevision({"mechanism": SUBJECT}, pass_id="fixture-second",
                           file="owned.c", function="f", line_start=1)
    receipts = (replace(_receipt(), claim_revision=first), replace(_receipt(), claim_revision=second))
    assert record_refutation_basis(_history(), origin=ORIGIN, attempt_id="fixture-attempt",
        hypotheses=[SUBJECT], receipts=receipts) is None
    assert record_refutation_basis(_history(), origin=ORIGIN, attempt_id="fixture-attempt",
        hypotheses=[SUBJECT], receipts=list(reversed(receipts))) is None


@pytest.mark.parametrize("receipt", [
    replace(_receipt(), file="other.c"), replace(_receipt(), function="other"),
    replace(_receipt(), line_start=2), replace(_receipt(), source_identity=None),
    replace(_receipt(), source_identity=SourceIdentity("b" * 64, (1, 2, 40, 4, 5))),
    replace(_receipt(), hypothesis="different concern"), replace(_receipt(), checks=()),
    replace(_receipt(), checks=(ProbeOutcome("fixture", "confirmed", "fixture:scoped-negative"),)),
    replace(_receipt(), checks=(ProbeOutcome("smt_invariant", "refuted", "fixture:scoped-negative"),)),
])
def test_unbound_or_non_refuting_receipt_cannot_be_snapshotted(receipt):
    assert record_refutation_basis(_history(), origin=ORIGIN, attempt_id="fixture-attempt",
        hypotheses=[SUBJECT], receipts=(receipt,)) is None


@pytest.mark.parametrize("hypotheses,receipts", [
    ([], (_receipt(),)), ([SUBJECT], ()), ([SUBJECT, SUBJECT], (_receipt(),)),
    ([SUBJECT, "uncovered concern"], (_receipt(),)), ([SUBJECT], (_receipt(), _receipt())),
    ([SUBJECT] * 65, (_receipt(),)), ([None], (_receipt(),)),
])
def test_missing_duplicate_uncovered_and_oversized_enumerations_stay_unavailable(hypotheses, receipts):
    assert record_refutation_basis(_history(), origin=ORIGIN, attempt_id="fixture-attempt",
        hypotheses=hypotheses, receipts=receipts) is None


def test_wrong_attempt_and_missing_source_cannot_borrow_a_review_binding():
    assert record_refutation_basis(_history(), origin=ORIGIN, attempt_id="other",
        hypotheses=[SUBJECT], receipts=(_receipt(),)) is None
    assert record_refutation_basis(_history(), origin=replace(ORIGIN, source_identity=None),
        attempt_id="fixture-attempt", hypotheses=[SUBJECT], receipts=(_receipt(),)) is None


def test_label_without_an_enumerated_snapshot_remains_unavailable():
    recorded = record_assessment_basis(_history(), origin=ORIGIN, attempt_id="fixture-attempt",
                                       status="clean", basis="enumerated_claims_refuted")
    assert recorded is not None
    assert read_assessment_basis(recorded, pass_id="fixture-pass", status="clean") is None


@pytest.mark.parametrize("fault", [
    "missing_subjects", "uncovered", "extra_record", "extra_check", "extra_source", "source_bool",
    "wrong_file", "wrong_line", "wrong_source", "not_refuted", "diagnostic_rule", "wrong_action",
    "missing_checks", "duplicate_record", "oversized", "extra_reference", "extra_material",
])
def test_saved_snapshot_cannot_expand_or_change_its_historical_scope(fault):
    recorded = _record()
    review = recorded["review"]
    row = review["assessment_refutations"][0]
    if fault == "missing_subjects":
        del review["assessment_hypotheses"]
    elif fault == "uncovered":
        review["assessment_hypotheses"].append("another concern")
    elif fault == "extra_record":
        row["assurance"] = "mechanically_verified"
    elif fault == "extra_check":
        row["checks"][0]["assurance"] = "mechanically_verified"
    elif fault == "extra_source":
        row["source_identity"]["build_closure"] = "complete"
    elif fault == "source_bool":
        row["source_identity"]["version"][0] = True
    elif fault == "wrong_file":
        row["file"] = "other.c"
    elif fault == "wrong_line":
        row["line_start"] = True
    elif fault == "wrong_source":
        row["source_identity"]["sha256"] = "b" * 64
    elif fault == "not_refuted":
        row["checks"][0]["verdict"] = "inconclusive"
    elif fault == "diagnostic_rule":
        row["checks"][0]["rule_id"] = "protocol_state:invariant-violated"
    elif fault == "wrong_action":
        row["action"] = "claim_verification"
    elif fault == "missing_checks":
        row["checks"] = []
    elif fault == "duplicate_record":
        review["assessment_refutations"].append(deepcopy(row))
    elif fault == "oversized":
        row["checks"][0]["reason"] = "x" * 20000
    elif fault == "extra_reference":
        row["claim_reference"] = {"claim_id": "fixture", "revision_id": "fixture", "assurance": "verified"}
    elif fault == "extra_material":
        row["material_admission"] = {"default_cwe": "", "declared_material": [],
            "role": "rejection_context_not_checker_scope", "build_closure": "complete"}
    assert read_refutation_basis(review) is None
    assert read_assessment_basis(recorded, pass_id="fixture-pass", status="clean") is None
