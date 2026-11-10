"""Delivered conditional reference text narrows reuse, not target authority."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json

import pytest

from core.audit import reference_inputs as inputs
from core.audit.knowledge_context import reference_delivery, reference_sections
from core.audit.review_context_inputs import context_inputs_from_sources, context_inputs_digest
from core.language_reference import ReferenceContext, lookup


def _answer(entry_id="c.integer-conversion", request_id="owned"):
    return lookup(request_id, "", ReferenceContext("c"), entry_id=entry_id)


def _delivery(answer, *, delivered=True):
    return reference_delivery((answer,), reference_sections((answer,)) if delivered else [])


def _manifest(answer=None):
    answer = answer or _answer()
    return inputs.reference_inputs_from_delivery(_delivery(answer), (answer,))


def test_actual_delivery_captures_exact_rendered_entries_not_request_or_topic():
    answer = _answer()
    manifest = _manifest(answer)
    entry, = answer.entries
    assert manifest == {"version": 1, "role": "review-reference-inputs", "complete": True,
                        "entries": [{"id": entry.entry_id, "version": entry.version,
                                     "pack_version": answer.pack_version,
                                     "sha256": hashlib.sha256(entry.render_core().encode()).hexdigest()}]}
    assert inputs.reference_inputs_digest(manifest)
    assert inputs.reference_inputs_current(manifest)
    assert _manifest(replace(answer, request_id="other-request")) == manifest
    assert "owned" not in json.dumps(manifest)


def test_prerequisites_travel_with_the_delivered_rule():
    manifest = _manifest(_answer("c.integer-usual-conversions"))
    assert {row["id"] for row in manifest["entries"]} == {
        "c.integer-promotion", "c.integer-usual-conversions"}
    assert inputs.reference_inputs_current(manifest)


def test_explicit_omission_is_distinct_from_missing_or_unknown_delivery():
    answer = _answer()
    assert inputs.reference_inputs_from_delivery(_delivery(answer, delivered=False), (answer,)) is None
    assert inputs.reference_inputs_from_delivery([], ()) is None
    assert inputs.reference_inputs_from_delivery(None, ()) is None
    for rows in (None, [], {}, [{"request_id": "unknown", "delivered": True}],
                 [{"request_id": [], "delivered": True}], [{"delivered": 1}]):
        manifest = inputs.reference_inputs_from_delivery(rows, (answer,))
        assert manifest["complete"] is False
        assert inputs.reference_inputs_digest(manifest) is None
    conflict = _delivery(answer) + _delivery(answer, delivered=False)
    assert not inputs.reference_inputs_from_delivery(conflict, (answer,))["complete"]
    second = _answer(request_id="second")
    assert not inputs.reference_inputs_from_delivery(_delivery(answer), (answer, second))["complete"]


@pytest.mark.parametrize("change", ["pack", "id", "version", "boolean-version", "extra-key"])
def test_delivered_metadata_must_match_the_owned_answer(change):
    answer = _answer()
    rows = _delivery(answer)
    if change == "pack": rows[0]["pack_version"] = "different"
    elif change == "id": rows[0]["entries"][0]["id"] = "different"
    elif change == "version": rows[0]["entries"][0]["version"] += 1
    elif change == "boolean-version": rows[0]["entries"][0]["version"] = True
    else: rows[0]["entries"][0]["authority"] = "proof"
    manifest = inputs.reference_inputs_from_delivery(rows, (answer,))
    assert manifest["complete"] is False
    assert inputs.reference_inputs_digest(manifest) is None


@pytest.mark.parametrize("change", ["rule", "conditions", "citations", "edition", "version"])
def test_current_pack_changes_invalidate_delivered_content_even_without_version_bump(monkeypatch, change):
    from core.language_reference import c_integer

    answer = _answer()
    old = _manifest(answer)
    entry = answer.entries[0]
    if change == "rule": updated = replace(entry, rule=entry.rule + " Clarification.")
    elif change == "conditions": updated = replace(entry, conditions=(*entry.conditions, "Additional condition."))
    elif change == "citations": updated = replace(entry, citations=(*entry.citations, "Additional citation."))
    elif change == "edition": updated = replace(entry, editions=("different-edition",))
    else: updated = replace(entry, version=entry.version + 1)
    monkeypatch.setattr(c_integer, "ENTRIES", tuple(updated if item.entry_id == entry.entry_id else item
                                                  for item in c_integer.ENTRIES))
    assert not inputs.reference_inputs_current(old)
    assert inputs.reference_inputs_digest(old), "record identity is separate from currentness"


def test_unrelated_pack_edit_does_not_invalidate_delivered_entries(monkeypatch):
    from core.language_reference import c_integer

    old = _manifest()
    supplied = {row["id"] for row in old["entries"]}
    other = next(entry for entry in c_integer.ENTRIES if entry.entry_id not in supplied)
    monkeypatch.setattr(c_integer, "ENTRIES", tuple(
        replace(entry, rule=entry.rule + " Clarification.") if entry == other else entry
        for entry in c_integer.ENTRIES))
    assert inputs.reference_inputs_current(old)


def test_exact_deduplication_and_conflict_loss_remain_distinct():
    first = _manifest()
    assert inputs.merge_reference_inputs(None, first, first) == first
    assert inputs.merge_reference_inputs(None, None) is None
    assert inputs.merge_reference_inputs(first, {})["complete"] is False
    conflicting = deepcopy(first)
    conflicting["entries"][0]["sha256"] = "a" * 64
    merged = inputs.merge_reference_inputs(first, conflicting)
    assert merged["complete"] is False
    assert len(merged["entries"]) == 2
    assert inputs.reference_inputs_digest(merged) is None
    assert not inputs.reference_inputs_current(merged)
    assert inputs.merge_reference_inputs(merged, first)["complete"] is False


def test_entry_and_byte_caps_retain_an_explicit_incomplete_record(monkeypatch):
    manifest = _manifest()
    many = []
    for index in range(inputs.MAX_ENTRIES + 1):
        row = deepcopy(manifest)
        row["entries"][0]["id"] = f"entry-{index}"
        many.append(row)
    capped = inputs.merge_reference_inputs(*many)
    assert len(capped["entries"]) == inputs.MAX_ENTRIES
    assert capped["complete"] is False
    assert len(json.dumps(capped).encode()) < inputs.MAX_SNAPSHOT_BYTES
    monkeypatch.setattr(inputs, "MAX_SNAPSHOT_BYTES", 100)
    assert inputs.merge_reference_inputs(manifest)["complete"] is False
    assert inputs.reference_inputs_digest(manifest) is None


@pytest.mark.parametrize("mutation", ["unknown-field", "wrong-role", "wrong-version", "bool-version",
                                      "wrong-complete", "bad-digest", "missing-id", "row-extra", "too-many"])
def test_malformed_portable_records_never_become_reusable(mutation):
    value = _manifest()
    if mutation == "unknown-field": value["loader"] = "ignored"
    elif mutation == "wrong-role": value["role"] = "proof"
    elif mutation == "wrong-version": value["version"] = 2
    elif mutation == "bool-version": value["version"] = True
    elif mutation == "wrong-complete": value["complete"] = 1
    elif mutation == "bad-digest": value["entries"][0]["sha256"] = "A" * 64
    elif mutation == "missing-id": value["entries"][0].pop("id")
    elif mutation == "row-extra": value["entries"][0]["path"] = "/not/read"
    else: value["entries"] *= inputs.MAX_ENTRIES + 1
    assert inputs.reference_inputs_digest(value) is None
    assert not inputs.reference_inputs_current(value)
    assert inputs.merge_reference_inputs(value, _manifest())["complete"] is False


def test_combined_digest_preserves_legacy_source_only_contract():
    source = context_inputs_from_sources((("target", "unit.c", "a" * 64),))
    reference = _manifest()
    assert inputs.review_context_digest(source) == context_inputs_digest(source)
    assert inputs.review_context_digest(source, None) == context_inputs_digest(source)
    combined = inputs.review_context_digest(source, reference)
    assert combined and combined != context_inputs_digest(source)
    assert combined != inputs.review_context_digest(source, _manifest(_answer("c.integer-promotion")))
    assert inputs.review_context_digest(source, {}) is None
    assert inputs.review_context_digest({**source, "complete": False}, reference) is None
