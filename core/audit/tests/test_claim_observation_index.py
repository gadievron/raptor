"""Claim indexing retains provenance without deciding claim truth."""

from copy import deepcopy
from itertools import permutations
import json
from uuid import uuid4

import pytest

from core.audit import check_trace
from core.audit.claim_observations import index_claim_observations
from core.audit.claims import ClaimRevision
from core.audit.claim_verification import ClaimVerification
from core.audit.record import load_verified_audit_log
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import ToolChainResult, VerificationScope


def _event(tmp_path, revision=None, hypothesis=None, *, legacy=False, receipts=(), refuted=False, binding=None):
    hypothesis = hypothesis or (revision.hypothesis if revision is not None else {
        "mechanism": "discarded error", "assumptions": ["caller checks the return value"],
    })
    if revision is None and not legacy:
        revision = ClaimRevision(hypothesis, pass_id=uuid4().hex, file="a.c", function="f", line_start=4)
    out = tmp_path / uuid4().hex
    out.mkdir()
    check_trace.record_claim_observations(
        out, file="a.c", function="f", line_start=4,
        verifications=[ClaimVerification(hypothesis, receipts, refuted, binding=binding, claim_revision=revision)],
    )
    row, = load_verified_audit_log(out)
    row.pop("integrity", None)
    return row, revision


def _check(tmp_path, revision, *, verdict="confirmed"):
    out = tmp_path / uuid4().hex
    out.mkdir()
    results = ToolChainResult(file=revision.file, function=revision.function, line_start=revision.line_start,
                              hypothesis=revision.hypothesis["mechanism"], claim_revision=revision)
    check_trace.record_check_observation(out, results, tool="semgrep", verdict=verdict, rule_id="fixture")
    row, = load_verified_audit_log(out)
    row.pop("integrity", None)
    return row


def _reference(event, index=0):
    return {"event_id": event["id"], "index": index}


def test_index_links_pipeline_ids_and_retains_raw_statement_only_once(tmp_path):
    marker = "the full statement must stay in the raw observation"
    hypothesis = {"mechanism": marker, "claim_id": "model-supplied", "revision_id": "model-supplied"}
    event, revision = _event(tmp_path, hypothesis=hypothesis, receipts=("semgrep:alleged",))
    check = _check(tmp_path, revision)
    result = index_claim_observations([event], [check])
    claim, = result["claims"]
    assert claim["claim_reference"] == revision.event_reference()
    assert claim["definition"] == revision.reference()
    assert claim["statement_reference"] == _reference(event)
    assert claim["observations"] == [_reference(event)]
    assert claim["producer_check_ids"] == [check["id"]]
    assert claim["adjudication"] == "unadjudicated"
    assert marker not in json.dumps(claim)
    assert "model-supplied" not in json.dumps(claim)
    assert result["quarantined_revisions"] == []
    assert result["unavailable_inputs"] == []
    assert result["rejected_check_links"] == []
    assert event["observations"]["data"]["details"][0]["hypothesis"] == hypothesis


def test_repeated_definition_coalesces_without_confusing_observations_with_identity(tmp_path):
    first, revision = _event(tmp_path, receipts=("semgrep:first",))
    binding = VerificationScope("a.c", "f", 4, revision.hypothesis["mechanism"], SourceIdentity("a" * 64, (1, 2, 3, 4, 5)))
    later, _ = _event(tmp_path, revision, refuted=True, binding=binding)
    check = _check(tmp_path, revision, verdict="refuted")
    expected_refs = sorted([_reference(first), _reference(later)], key=lambda row: (row["event_id"], row["index"]))
    outputs = [index_claim_observations(list(order), [check, deepcopy(check)])
               for order in permutations([first, later])]
    assert outputs[0] == outputs[1]
    claim, = outputs[0]["claims"]
    assert claim["observations"] == expected_refs
    assert claim["statement_reference"] == expected_refs[0]
    assert claim["producer_check_ids"] == [check["id"]]
    assert claim["adjudication"] == "unadjudicated"
    assert outputs[0]["quarantined_revisions"] == []


@pytest.mark.parametrize("change", ["statement", "occurrence", "claim_id"])
def test_conflicting_revision_definitions_quarantine_every_variant_in_any_order(tmp_path, change):
    original, revision = _event(tmp_path)
    variant = deepcopy(original)
    variant["id"] = uuid4().hex
    if change == "statement":
        # Equal mechanism text must not hide a changed premise.
        variant["observations"]["data"]["details"][0]["hypothesis"]["assumptions"] = ["caller never checks"]
    elif change == "occurrence":
        variant["claim_revisions"][0]["file"] = "other.c"
    else:
        variant["claim_revisions"][0]["claim_id"] = uuid4().hex
    independent, other = _event(tmp_path)
    check = _check(tmp_path, revision)
    outputs = [index_claim_observations(list(order), [check])
               for order in permutations([original, variant, independent])]
    assert all(result == outputs[0] for result in outputs)
    claim, = outputs[0]["claims"]
    assert claim["claim_reference"] == other.event_reference()
    quarantined = outputs[0]["quarantined_revisions"]
    assert len(quarantined) == 1
    assert quarantined[0]["revision_id"] == revision.revision_id
    assert revision.revision_id not in json.dumps(outputs[0]["claims"])


@pytest.mark.parametrize("field,value", [("claim_id", "not-a-uuid"), ("revision", True), ("revision", 0)])
def test_malformed_variant_with_a_known_revision_id_cannot_leave_a_valid_winner(tmp_path, field, value):
    original, revision = _event(tmp_path)
    malformed = deepcopy(original)
    malformed["id"] = uuid4().hex
    malformed["claim_revisions"][0][field] = value
    outputs = [index_claim_observations(list(order), []) for order in permutations([original, malformed])]
    assert outputs[0] == outputs[1]
    assert outputs[0]["claims"] == []
    quarantine, = outputs[0]["quarantined_revisions"]
    assert quarantine["revision_id"] == revision.revision_id


@pytest.mark.parametrize("field,value", [("file", "other.c"), ("function", "g"),
                                        ("line_start", 5), ("hypothesis", "another concern")])
def test_matching_ids_do_not_link_a_different_checker_scope(tmp_path, field, value):
    event, revision = _event(tmp_path)
    exact = _check(tmp_path, revision)
    wrong = deepcopy(exact)
    wrong["id"] = uuid4().hex
    wrong["scope"][field] = value
    result = index_claim_observations([event], [wrong, exact])
    claim, = result["claims"]
    assert claim["producer_check_ids"] == [exact["id"]]
    assert wrong["id"] in json.dumps(result["rejected_check_links"])
    assert claim["adjudication"] == "unadjudicated"


@pytest.mark.parametrize("reference_kind", ["missing", "other_claim", "other_revision"])
def test_text_and_location_alone_never_supply_a_producer_link(tmp_path, reference_kind):
    event, revision = _event(tmp_path)
    check = _check(tmp_path, revision)
    if reference_kind == "missing":
        check.pop("claim_reference")
    elif reference_kind == "other_claim":
        check["claim_reference"]["claim_id"] = uuid4().hex
    else:
        check["claim_reference"]["revision_id"] = uuid4().hex
    result = index_claim_observations([event], [check])
    claim, = result["claims"]
    assert claim["producer_check_ids"] == []
    assert claim["adjudication"] == "unadjudicated"


@pytest.mark.parametrize("missing", ["partial_statement", "partial_lineage", "legacy_field", "legacy_entry"])
def test_unavailable_inputs_remain_visible_without_synthetic_claims(tmp_path, missing):
    if missing == "partial_statement":
        event, _ = _event(tmp_path, hypothesis={"mechanism": "x" * (80 * 1024)})
        assert event["observations"]["complete"] is False
    else:
        event, _ = _event(tmp_path, legacy=missing == "legacy_entry")
        if missing == "partial_lineage":
            event["claim_revisions"] = None
            event["claim_revisions_complete"] = False
            event["metadata_omissions"].append("claim_revisions_size_limit")
        elif missing == "legacy_field":
            event.pop("claim_revisions")
            event.pop("claim_revisions_complete")
    result = index_claim_observations([event], [])
    assert result["claims"] == []
    assert result["unavailable_inputs"]
    assert event["id"] in json.dumps(result["unavailable_inputs"])


def test_index_does_not_mutate_claim_or_checker_inputs(tmp_path):
    event, revision = _event(tmp_path)
    check = _check(tmp_path, revision)
    events, checks = [event], [check]
    original = deepcopy((events, checks))
    result = index_claim_observations(events, checks)
    assert result["claims"]
    assert (events, checks) == original


def test_malformed_statement_variant_quarantines_known_revision(tmp_path):
    original, revision = _event(tmp_path)
    malformed = deepcopy(original)
    malformed["id"] = uuid4().hex
    malformed["observations"]["data"]["details"][0]["hypothesis"] = None
    results = [index_claim_observations(list(order), []) for order in permutations([original, malformed])]
    assert results[0] == results[1]
    assert results[0]["claims"] == []
    quarantined, = results[0]["quarantined_revisions"]
    assert quarantined["revision_id"] == revision.revision_id
