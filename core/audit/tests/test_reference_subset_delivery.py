"""Reference receipts recognise complete reading in an actually retained bundle."""

from dataclasses import replace

import pytest

from core.audit.context import format_context_for_prompt
from core.audit.knowledge_context import reference_delivery, reference_sections
from core.audit.reference_inputs import (
    reference_answer_already_delivered,
    reference_inputs_digest,
    reference_inputs_from_delivery,
)
from core.language_reference import ReferenceContext, lookup
from core.llm.prompt_budget import fit_to_budget


def _division():
    return lookup("division-owned", "", ReferenceContext("c"), entry_id="c.integer-division")


def _conversion():
    return lookup("conversion-owned", "integer conversion", ReferenceContext("c"))


@pytest.mark.parametrize("superset_first", [True, False])
def test_retained_whole_bundle_delivers_its_complete_subset(superset_first):
    division, conversion = _division(), _conversion()
    answers = (division, conversion) if superset_first else (conversion, division)
    assert conversion.entries and all(entry in division.entries for entry in conversion.entries)
    source = 'int f(int a) { const char *padding="' + "x" * 17500 + '"; return a; }'
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source, "language_reference_answers": answers}
    prompt = format_context_for_prompt(ctx, budget_limit=6000)
    assert source in prompt
    assert all(entry.render_core() in prompt for entry in division.entries)
    for entry in conversion.entries:
        assert prompt.count(entry.render_core()) == 1
        assert entry.conditions and entry.citations and entry.required_target_facts
    delivery = ctx["language_reference_delivery"]
    assert {row["request_id"] for row in delivery} == {division.request_id, conversion.request_id}
    assert all(row["delivered"] and row["reason"] == "delivered" for row in delivery)

    # Recognising shared reading cannot create a different content dependency.
    combined = reference_inputs_from_delivery(delivery, answers)
    single_delivery = reference_delivery((division,), reference_sections((division,)))
    single = reference_inputs_from_delivery(single_delivery, (division,))
    assert combined == single
    assert reference_inputs_digest(combined) == reference_inputs_digest(single)
    assert reference_answer_already_delivered(conversion, combined)


def test_unretained_superset_does_not_remove_small_requested_fallback():
    conversion = lookup("small-owned", "", ReferenceContext("c"), entry_id="c.integer-conversion")
    division = replace(_division(), request_id="large-topic", selection_kind="topic")
    answers = (conversion, division)
    sections = reference_sections(answers)
    assert len(sections) == 2 and sections[0].token_estimate < sections[1].token_estimate
    kept, shed = fit_to_budget(sections, budget_tokens=sections[0].token_estimate)
    assert kept == [sections[0]] and shed == [sections[1]]
    assert all(entry.render_core() in kept[0].text for entry in conversion.entries)
    assert division.entries[-1].render_core() not in kept[0].text
    rows = {row["request_id"]: row for row in reference_delivery(answers, kept)}
    assert rows[conversion.request_id]["delivered"]
    assert not rows[division.request_id]["delivered"]
    assert rows[division.request_id]["reason"] == "reference_too_large"


@pytest.mark.parametrize("difference", [
    "rule", "summary", "edition", "pack", "status", "reason", "missing_facts", "prerequisite",
])
def test_retained_subset_requires_full_content_and_compatible_envelope(difference):
    supplier, wanted = _division(), _conversion()
    if difference in ("rule", "summary", "edition"):
        original = wanted.entries[0]
        fields = {"rule": original.rule + " A separate reviewed condition.",
                  "summary": original.summary + " Separate ranking metadata.",
                  "edition": ("c23",)}
        field = "editions" if difference == "edition" else difference
        changed = replace(original, **{field: fields[difference]})
        assert (changed.entry_id, changed.version) == (original.entry_id, original.version)
        if difference == "summary":
            assert changed.render_core() == original.render_core()
        wanted = replace(wanted, entries=(changed,))
    elif difference == "pack":
        wanted = replace(wanted, pack_version="c-integers-other")
    elif difference == "status":
        wanted = replace(wanted, status="ambiguous")
    elif difference == "reason":
        wanted = replace(wanted, reason="Different applicability remains unresolved.")
    elif difference == "missing_facts":
        wanted = replace(wanted, missing_facts=("language edition", "configured integer range"))
    else:
        wanted = replace(lookup("prerequisite-owned", "", ReferenceContext("c"),
                                entry_id="c.integer-usual-conversions"), selection_kind="topic")
        assert "c.integer-promotion" in wanted.entries[-1].prerequisites
        supplier = replace(supplier, entries=tuple(entry for entry in supplier.entries
                           if entry.entry_id != "c.integer-promotion"))
        assert all(entry.entry_id != "c.integer-promotion" for entry in supplier.entries)

    answers = (supplier, wanted)
    sections = reference_sections(answers)
    # Different bundles ensure this reaches the new subset-recognition path,
    # rather than the existing whole-answer alias behaviour.
    assert len(sections) == 2 and sections[0].label != sections[1].label
    assert sections[0].priority < sections[1].priority
    kept, _ = fit_to_budget(sections, budget_tokens=sections[0].token_estimate)
    assert kept == [sections[0]] and sections[1].label not in {section.label for section in kept}
    rows = reference_delivery(answers, kept)
    assert rows[0]["delivered"]
    assert rows[1]["request_id"] == wanted.request_id
    assert not rows[1]["delivered"]
    assert rows[1]["reason"] == "reference_too_large"
