"""Model withdrawal refers only to a supplied exact claim and source window."""

from copy import deepcopy
import json
from uuid import uuid4

import pytest

from core.audit.claims import ClaimRevision
from core.audit.claim_withdrawal import MAX_PAYLOAD_BYTES, MAX_PROPOSALS, evaluate_withdrawals


def case():
    revision = ClaimRevision({"mechanism": "negative length becomes an oversized copy", "cwe": "CWE-195",
                              "counter": {"premise": "length is signed"}},
                             pass_id=uuid4().hex, file="src/a.c", function="f", line_start=10)
    definition = {"reference": revision.reference(), "hypothesis": revision.hypothesis}
    fragment = {"fragment_id": uuid4().hex, "file": "src/a.c", "function": "f",
                "line_start": 10, "line_end": 12,
                "source": "unsigned f(unsigned length) {\n    return length;\n}\n"}
    proposal = {**revision.event_reference(), "corrected_premise": "The parameter is unsigned.",
                "reason": "The earlier negative-input premise does not describe this declaration.",
                "source_anchors": [{"fragment_id": fragment["fragment_id"], "line_start": 10, "line_end": 10}],
                "remaining_unknowns": []}
    return definition, fragment, proposal


def evaluate(proposals, claims, source):
    return evaluate_withdrawals(proposals, delivered_claims=claims, source_fragment=source,
                               file="src/a.c", function="f", line_start=10)


def test_valid_explicit_withdrawal_preserves_exact_definition_without_proof_authority():
    definition, fragment, proposal = case()
    before = deepcopy((definition, fragment, proposal))
    result = evaluate([proposal], [definition], fragment)
    accepted, = result["accepted"]
    assert result["rejected"] == []
    assert accepted["reference"] == definition["reference"]
    assert accepted["hypothesis"] == definition["hypothesis"]
    assert accepted["adjudication"] == "model_withdrawn"
    assert "refuted" not in accepted and "receipts" not in accepted
    assert "source" not in accepted
    accepted["hypothesis"]["counter"]["premise"] = "mutated result"
    assert (definition, fragment, proposal) == before


@pytest.mark.parametrize("fault,reason", [
    ("guessed_revision", "claim_definition_unavailable"),
    ("wrong_claim", "claim_definition_unavailable"),
    ("uppercase_id", "invalid_claim_reference"),
    ("no_anchor", "source_anchor_unavailable"),
    ("unseen_caller", "source_anchor_unavailable"),
    ("before_fragment", "source_anchor_unavailable"),
    ("after_fragment", "source_anchor_unavailable"),
    ("reversed_anchor", "source_anchor_unavailable"),
    ("bool_line", "source_anchor_unavailable"),
    ("unknown_caller_guarantee", "remaining_unknowns"),
    ("missing_unknowns", "remaining_unknowns"),
    ("missing_reason", "missing_or_oversized_explanation"),
    ("long_premise", "missing_or_oversized_explanation"),
])
def test_refusal_preserves_the_claim_instead_of_inventing_a_withdrawal(fault, reason):
    definition, fragment, proposal = case()
    if fault == "guessed_revision":
        proposal["revision_id"] = uuid4().hex
    elif fault == "wrong_claim":
        proposal["claim_id"] = uuid4().hex
    elif fault == "uppercase_id":
        proposal["claim_id"] = "A" * 32
    elif fault == "no_anchor":
        proposal["source_anchors"] = []
    elif fault == "unseen_caller":
        proposal["source_anchors"][0]["fragment_id"] = uuid4().hex
    elif fault == "before_fragment":
        proposal["source_anchors"][0]["line_start"] = 9
    elif fault == "after_fragment":
        proposal["source_anchors"][0]["line_end"] = 13
    elif fault == "reversed_anchor":
        proposal["source_anchors"][0].update(line_start=12, line_end=10)
    elif fault == "bool_line":
        proposal["source_anchors"][0]["line_start"] = True
    elif fault == "unknown_caller_guarantee":
        proposal["remaining_unknowns"] = ["caller bound is unknown"]
    elif fault == "missing_unknowns":
        del proposal["remaining_unknowns"]
    elif fault == "missing_reason":
        proposal["reason"] = " "
    else:
        proposal["corrected_premise"] = "x" * 1025
    result = evaluate([proposal], [definition], fragment)
    assert result == {"accepted": [], "rejected": [{"index": 0, "reason": reason}]}


@pytest.mark.parametrize("fault", ["changed_cwe", "changed_premise", "invalid_variant", "other_occurrence"])
def test_conflicting_revision_variants_quarantine_all_arrival_orders(fault):
    definition, fragment, proposal = case()
    other = deepcopy(definition)
    if fault == "changed_cwe":
        other["hypothesis"]["cwe"] = "CWE-190"
    elif fault == "changed_premise":
        other["hypothesis"]["counter"]["premise"] = "different premise"
    elif fault == "invalid_variant":
        other["reference"]["revision"] = True
    else:
        other["reference"]["file"] = "src/caller.c"
    for rows in ([definition, other], [other, definition]):
        result = evaluate([proposal], rows, fragment)
        assert result["accepted"] == []
        assert result["rejected"] == [{"index": 0, "reason": "claim_definition_unavailable"}]


def test_exact_duplicate_definitions_coalesce_but_duplicate_proposals_all_refuse():
    definition, fragment, proposal = case()
    assert len(evaluate([proposal], [definition, deepcopy(definition)], fragment)["accepted"]) == 1
    conflicting = {**proposal, "reason": "a different reason"}
    result = evaluate([proposal, conflicting], [definition], fragment)
    assert result["accepted"] == []
    assert result["rejected"] == [{"index": i, "reason": "duplicate_revision_proposal"} for i in range(2)]


@pytest.mark.parametrize("fault", ["absent", "wrong_occurrence", "wrong_line_count", "bool_end", "large_source"])
def test_undelivered_or_inconsistent_source_cannot_satisfy_an_anchor(fault):
    definition, fragment, proposal = case()
    if fault == "absent":
        fragment = None
    elif fault == "wrong_occurrence":
        fragment["function"] = "caller"
    elif fault == "wrong_line_count":
        fragment["line_end"] = 13
    elif fault == "bool_end":
        fragment["line_end"] = True
    else:
        fragment["source"] = "x" * (MAX_PAYLOAD_BYTES + 1)
    assert evaluate([proposal], [definition], fragment) == {
        "accepted": [], "rejected": [{"index": 0, "reason": "source_fragment_unavailable"}]}


def test_source_line_model_does_not_treat_unicode_comment_characters_as_new_lines():
    definition, fragment, proposal = case()
    fragment["source"] = "unsigned f(unsigned length) { /* \u2028 comment */\r\n    return length;\r\n}\r\n"
    assert len(evaluate([proposal], [definition], fragment)["accepted"]) == 1


@pytest.mark.parametrize("proposals", [None, []])
def test_no_proposal_withdraws_nothing(proposals):
    assert evaluate(proposals, [], None) == {"accepted": [], "rejected": []}


def test_malformed_and_excessive_inputs_disclose_refusal_without_echoing_payload():
    definition, fragment, proposal = case()
    assert evaluate({"body": "clean"}, [definition], fragment)["rejected"] == [
        {"index": None, "reason": "malformed_proposals"}]
    result = evaluate([proposal] * (MAX_PROPOSALS + 1), [definition], fragment)
    assert result == {"accepted": [], "rejected": [
        {"index": None, "reason": "proposal_payload_limit", "count": MAX_PROPOSALS + 1}]}
    proposal["reason"] = "unbounded-secret-text" * MAX_PAYLOAD_BYTES
    result = evaluate([proposal], [definition], fragment)
    assert len(json.dumps(result)) < 200
    assert "unbounded-secret-text" not in json.dumps(result)


def test_one_invalid_proposal_does_not_hide_an_independent_valid_decision():
    definition, fragment, proposal = case()
    result = evaluate([{"body": "clean"}, proposal], [definition], fragment)
    assert len(result["accepted"]) == 1
    assert result["rejected"] == [{"index": 0, "reason": "invalid_claim_reference"}]


def test_cyclic_or_deep_proposal_payload_is_refused_without_recursive_output():
    definition, fragment, proposal = case()
    cycle = []
    cycle.append(cycle)
    proposal["extra"] = cycle
    assert evaluate([proposal], [definition], fragment)["rejected"] == [
        {"index": None, "reason": "proposal_payload_limit", "count": 1}]
    nested = []
    for _ in range(40):
        nested = [nested]
    proposal["extra"] = nested
    assert evaluate([proposal], [definition], fragment)["accepted"] == []
