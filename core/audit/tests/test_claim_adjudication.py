"""Pure reducer counterexamples; no analysis backend is invoked."""
from dataclasses import replace
from itertools import permutations

from core.audit.claim_adjudication import (
    ClaimChange, ClaimContext, ClaimContract, FactEvent, reduce_claims,
)
from core.audit.refutation_source import SourceIdentity

CONTRACTS = {"whole": ClaimContract("checker", "1", frozenset({"reach", "effect"}), frozenset({"reach"}))}
CONTEXT = ClaimContext("claim", "rev", SourceIdentity("digest", (1,)), "whole", ("dep",), ("abi",), ("a", "f", 1))


def fact(event_id="a", obligation="reach", **kwargs):
    return replace(FactEvent(event_id, CONTEXT, obligation, "checker", "1", "completed",
                             "supports_fact", "request", "request", True, "raw"), **kwargs)


def reduce(events, **kwargs):
    return reduce_claims([CONTEXT], events, contracts=CONTRACTS, **kwargs)


def test_whole_claim_needs_every_obligation():
    assert reduce([fact()])["claims"][0]["state"] == "unresolved"
    assert reduce([fact(), fact("b", "effect")])["claims"][0]["state"] == "supported"


def test_order_and_duplicate_identity():
    events = [fact(), fact("b", "effect"), fact()]
    values = [reduce(list(order)) for order in permutations(events)]
    assert all(value == values[0] for value in values)
    result = reduce([fact(), fact(semantic="contradicts_fact")])
    assert result["quarantined_event_ids"] == ["a"]
    assert result["claims"][0]["state"] == "unresolved"


def test_negative_authority_is_scoped_and_execution_is_separate():
    for change in ({"execution": "timed_out"}, {"semantic": "no_match"},
                   {"complete": False}, {"executed_request_id": "other"},
                   {"adapter": "model"}, {"context": replace(CONTEXT, assumptions=("other",))},
                   {"context": replace(CONTEXT, source=SourceIdentity("changed", (2,)))}):
        assert reduce([fact(**change)])["claims"][0]["state"] == "unresolved"
    assert reduce([fact(semantic="contradicts_fact")])["claims"][0]["state"] == "refuted"
    assert reduce([fact("n", "effect", semantic="contradicts_fact")])["claims"][0]["state"] == "unresolved"
    assert reduce([fact(), fact("n", semantic="contradicts_fact")])["claims"][0]["state"] == "conflicted"


def change(kind="withdrawn", **kwargs):
    reasons = {"withdrawn": "unsupported_theory_withdrawal", "invalidated": "source_changed",
               "superseded": "explicit_claim_revision"}
    return replace(ClaimChange("change", "claim", "rev", kind, CONTEXT,
                               reasons[kind], "grounded-record"), **kwargs)


def test_unsubstantiated_withdrawal_cannot_erase_supported_facts():
    facts = [fact(), fact("b", "effect")]
    for withdrawal in (ClaimChange("change", "claim", "rev", "withdrawn"), change(),
                       change(evidence_reference=""), change(context=replace(CONTEXT, assumptions=("other",)))):
        result = reduce(facts, changes=[withdrawal])["claims"][0]
        assert result["state"] == "supported"
        assert "change" in result["rejected_event_ids"]
    partial = reduce([fact()], changes=[change()])["claims"][0]
    assert partial["state"] == "withdrawn"
    assert partial["supported_obligations"] == ["reach"]
    assert partial["missing_obligations"] == ["effect"]
    assert partial["accepted_event_ids"] == ["a", "change"]
    assert reduce([], changes=[change()])["claims"][0]["state"] == "withdrawn"
    assert reduce([fact(semantic="contradicts_fact")], changes=[change()])["claims"][0]["state"] == "refuted"


def test_invalidation_requires_exact_context_and_targets_only_named_events():
    facts = [fact(), fact("b", "effect"), fact("c", "effect")]
    invalidation = change("invalidated", target_event_ids=frozenset({"b"}))
    # Independent replacement support remains admitted.
    result = reduce(facts, changes=[invalidation])["claims"][0]
    assert result["state"] == "supported"
    assert result["accepted_event_ids"] == ["a", "c", "change"]
    assert reduce(facts[:2], changes=[invalidation])["claims"][0]["state"] == "unresolved"
    for bad in (replace(invalidation, context=replace(CONTEXT, source=SourceIdentity("old", (0,)))),
                replace(invalidation, target_event_ids=frozenset({"absent"})),
                replace(invalidation, target_event_ids=frozenset()),
                replace(invalidation, reason="model_disagrees"),
                replace(invalidation, evidence_reference="")):
        assert reduce(facts[:2], changes=[bad])["claims"][0]["state"] == "supported"
    values = [reduce_claims([CONTEXT], order, contracts=CONTRACTS)
              for order in permutations([*facts[:2], invalidation])]
    assert all(value == values[0] for value in values)


def test_supersession_requires_registered_explicit_successor_link():
    facts = [fact(), fact("b", "effect")]
    successor = replace(CONTEXT, revision_id="new", parent_revision_id="rev")
    transition = change("superseded", successor=successor)
    result = reduce_claims([CONTEXT, successor], facts, contracts=CONTRACTS, changes=[transition])
    assert result["claims"][0]["revision_id"] == "new"
    assert result["claims"][0]["state"] == "unresolved"
    assert result["claims"][1]["state"] == "superseded"
    for bad in (replace(transition, successor=None),
                replace(transition, successor=replace(successor, parent_revision_id="other")),
                replace(transition, context=replace(CONTEXT, dependencies=("old",)))):
        assert reduce(facts, changes=[bad])["claims"][0]["state"] == "supported"
    assert reduce(facts, changes=[transition])["claims"][0]["state"] == "supported"


def test_ambiguous_lifecycle_event_cannot_restore_otherwise_supported_claim():
    changes = [ClaimChange("same", "claim", "rev", "invalidated"),
               ClaimChange("same", "claim", "rev", "withdrawn")]
    result = reduce([fact(), fact("b", "effect")], changes=changes)
    assert result["claims"][0]["state"] == "unresolved"
    assert result["quarantined_event_ids"] == ["same"]


def test_partial_fact_withdrawal_preserves_facts_without_transfer_or_refutation():
    events = [fact(), change()]
    values = [reduce_claims([CONTEXT], order, contracts=CONTRACTS)
              for order in permutations(events)]
    assert all(value == values[0] for value in values)
    row = values[0]["claims"][0]
    assert row["state"] == "withdrawn"
    assert row["supported_obligations"] == ["reach"]
    assert row["contradicted_obligations"] == []
    assert row["missing_obligations"] == ["effect"]
    assert row["accepted_event_ids"] == ["a", "change"]
    assert row["rejected_event_ids"] == []
    # Old facts remain on their original revision, not a new conclusion.
    revised = replace(CONTEXT, revision_id="other", parent_revision_id="rev")
    result = reduce_claims([CONTEXT, revised], events, contracts=CONTRACTS)
    new = next(row for row in result["claims"] if row["revision_id"] == "other")
    assert new["state"] == "unresolved"
    assert new["supported_obligations"] == []


def test_grounded_withdrawal_cannot_override_full_support_or_negative_authority():
    for events, state in (([fact(), fact("b", "effect")], "supported"),
                          ([fact(semantic="contradicts_fact")], "refuted"),
                          ([fact(), fact("n", semantic="contradicts_fact")], "conflicted")):
        row = reduce(events, changes=[change()])["claims"][0]
        assert row["state"] == state
        assert "change" in row["rejected_event_ids"]
    for bad in (change(context=replace(CONTEXT, assumptions=("invented",))),
                change(reason="model_disagrees"), change(evidence_reference=""),
                replace(change(), kind="unknown")):
        row = reduce([fact()], changes=[bad])["claims"][0]
        assert row["state"] == "unresolved"
        assert row["supported_obligations"] == ["reach"]
        assert "change" in row["rejected_event_ids"]
