"""Intersecting reading bundles share complete cores only after owned fitting."""

from dataclasses import replace

import pytest

from core.audit.context import format_context_for_prompt
from core.audit.knowledge_context import reference_delivery, reference_sections
from core.language_reference import ReferenceContext, lookup
from core.llm.prompt_budget import PromptSection, fit_to_budget


def _answers():
    context = ReferenceContext("c")
    division = lookup("division-owned", "", context, entry_id="c.integer-division")
    shift = lookup("shift-owned", "", context, entry_id="c.integer-shift")
    common = tuple(entry for entry in division.entries if entry in shift.entries)
    assert common
    assert not all(entry in division.entries for entry in shift.entries)
    assert not all(entry in shift.entries for entry in division.entries)
    return division, shift, common


def _share(answers, kept, originals):
    from core.audit.knowledge_context import dedupe_reference_sections

    return dedupe_reference_sections(answers, kept, rendered_sections=originals)


@pytest.mark.parametrize("budget", [100_000, 0], ids=["ample", "unlimited"])
@pytest.mark.parametrize("division_first", [True, False])
def test_actual_prompt_shares_complete_cores_between_intersecting_bundles(budget, division_first):
    division, shift, _ = _answers()
    answers = (division, shift) if division_first else (shift, division)
    source = "int f(int n, int d) { return (n / d) << 1; }"
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source, "language_reference_answers": answers}
    prompt = format_context_for_prompt(ctx, budget_limit=budget)
    assert source in prompt
    combined_entries = set(division.entries) | set(shift.entries)
    by_id = {entry.entry_id: entry for entry in combined_entries}
    for entry in combined_entries:
        assert prompt.count(entry.render_core()) == 1
        assert entry.conditions and entry.citations and entry.required_target_facts
        for prerequisite in entry.prerequisites:
            assert prompt.index(by_id[prerequisite].render_core()) < prompt.index(entry.render_core())
    rows = ctx["language_reference_delivery"]
    assert {row["request_id"] for row in rows} == {division.request_id, shift.request_id}
    assert all(row["delivered"] and row["reason"] == "delivered" for row in rows)
    assert all(row["missing_facts"] == ["language edition"] for row in rows)
    assert "Target language edition is unknown" in prompt


def test_union_only_shared_reading_keeps_its_own_label_and_receipt():
    from core.language_reference import c_integer

    base = lookup("base", "", ReferenceContext("c"), entry_id="c.integer-promotion")
    entries = {entry.entry_id: entry for entry in c_integer.ENTRIES}
    promotion = entries["c.integer-promotion"]
    conversion = entries["c.integer-conversion"]
    unary = entries["c.integer-unary-sign"]
    logical = entries["c.scalar-logical"]
    left = replace(base, request_id="left", entries=(promotion, unary))
    right = replace(base, request_id="right", entries=(conversion, logical))
    union = replace(base, request_id="union", entries=(promotion, conversion))
    answers = (left, right, union)
    assert not all(entry in left.entries for entry in union.entries)
    assert not all(entry in right.entries for entry in union.entries)
    sections = reference_sections(answers)
    reduced = _share(answers, sections, sections)
    assert [section.label for section in reduced] == [section.label for section in sections]
    union_section = next(section for section in reduced if section.label == sections[2].label)
    core_tail = "\n\n".join(entry.render_core() for entry in union.entries)
    assert union_section.text.startswith(sections[2].text[:-len(core_tail)])
    for entry in union.entries:
        assert entry.render_core() not in union_section.text
        assert f"{entry.entry_id} v{entry.version}" in union_section.text
    text = "\n".join(section.text for section in reduced)
    for entry in (promotion, conversion, unary, logical):
        assert text.count(entry.render_core()) == 1
    assert all(row["delivered"] for row in reference_delivery(answers, reduced))


def test_original_nonce_prefix_and_nonreference_sections_are_preserved(monkeypatch):
    division, shift, common = _answers()
    answers = (division, shift)
    references = reference_sections(answers)
    prefixes = {section.label: section.text[:-len("\n\n".join(
        entry.render_core() for entry in answer.entries))]
        for section, answer in zip(references, answers, strict=True)}
    assert all("<untrusted-" in prefix for prefix in prefixes.values())
    source = PromptSection("source", "int f(int n, int d) { return (n / d) << 1; }", 0)
    evidence = PromptSection("mechanical_evidence", "Scoped observation, not a verdict.", 0)
    kept = [source, *references, evidence]

    def forbidden_nonce():
        raise AssertionError("post-fit sharing must retain the original envelope nonce")

    monkeypatch.setattr("core.security.prompt_envelope._generate_nonce", forbidden_nonce)
    reduced = _share(answers, kept, references)
    assert reduced[0] is source and reduced[-1] is evidence
    assert kept == [source, *references, evidence]
    for section in reduced[1:-1]:
        assert section.text.startswith(prefixes[section.label])
    text = "\n".join(section.text for section in reduced)
    assert all(text.count(entry.render_core()) == 1 for entry in common)
    assert sum(section.token_estimate for section in reduced) < sum(
        section.token_estimate for section in kept)
    assert all(row["delivered"] for row in reference_delivery(answers, reduced))


@pytest.mark.parametrize("difference", ["prefix", "tail"])
def test_modified_section_is_untouched_and_cannot_seed_shared_cores(difference):
    division, shift, common = _answers()
    answers = (division, shift)
    originals = reference_sections(answers)
    text = ("Foreign prefix\n" + originals[0].text if difference == "prefix"
            else originals[0].text + "\nForeign trailing text")
    modified = replace(originals[0], text=text)
    kept = [modified, originals[1]]
    reduced = _share(answers, kept, originals)
    assert reduced[0] is modified
    assert reduced[1] is originals[1]
    assert all(entry.render_core() in reduced[1].text for entry in common)
    assert kept == [modified, originals[1]]


@pytest.mark.parametrize("difference", ["pack", "applicability"])
def test_intersection_sharing_does_not_cross_reading_envelopes(difference):
    division, shift, common = _answers()
    shift = (replace(shift, pack_version="c-integers-other") if difference == "pack"
             else replace(shift, missing_facts=("language edition", "configured integer range")))
    answers = (division, shift)
    sections = reference_sections(answers)
    reduced = _share(answers, sections, sections)
    assert reduced == sections
    assert all(after is prior for after, prior in zip(reduced, sections, strict=True))
    text = "\n".join(section.text for section in reduced)
    assert all(text.count(entry.render_core()) == 2 for entry in common)
    assert all(row["delivered"] for row in reference_delivery(answers, reduced))


def test_same_identity_with_changed_full_content_is_not_shared():
    division, shift, common = _answers()
    original = common[0]
    changed = replace(original, rule=original.rule + " A distinct reviewed condition.")
    assert (changed.entry_id, changed.version) == (original.entry_id, original.version)
    shift = replace(shift, entries=tuple(changed if entry == original else entry for entry in shift.entries))
    answers = (division, shift)
    sections = reference_sections(answers)
    reduced = _share(answers, sections, sections)
    text = "\n".join(section.text for section in reduced)
    assert text.count(original.render_core()) == 1
    assert text.count(changed.render_core()) == 1
    for entry in common[1:]:
        assert text.count(entry.render_core()) == 1
    assert all(row["delivered"] for row in reference_delivery(answers, reduced))


def test_mixed_pack_alias_section_keeps_its_complete_original_body():
    division, shift, _ = _answers()
    alias = replace(shift, request_id="other-pack-alias", pack_version="c-integers-other")
    answers = (division, shift, alias)
    sections = reference_sections(answers)
    assert len(sections) == 2
    before_rows = reference_delivery(answers, sections)
    assert all(row["delivered"] for row in before_rows)
    reduced = _share(answers, sections, sections)
    assert reduced == sections
    assert all(after is prior for after, prior in zip(reduced, sections, strict=True))
    assert reference_delivery(answers, reduced) == before_rows


def test_without_original_render_map_intersection_sharing_is_conservative():
    from core.audit.knowledge_context import dedupe_reference_sections

    division, shift, common = _answers()
    answers = (division, shift)
    sections = reference_sections(answers)
    reduced = dedupe_reference_sections(answers, sections)
    assert reduced == sections
    assert all(after is prior for after, prior in zip(reduced, sections, strict=True))
    text = "\n".join(section.text for section in reduced)
    assert all(text.count(entry.render_core()) == 2 for entry in common)


def test_shed_bundle_cannot_supply_cores_to_the_retained_fallback():
    division, shift, _ = _answers()
    answers = (division, shift)
    sections = reference_sections(answers)
    small_index = min(range(len(sections)), key=lambda index: sections[index].token_estimate)
    kept, shed = fit_to_budget(sections, budget_tokens=sections[small_index].token_estimate)
    assert kept == [sections[small_index]]
    assert len(shed) == 1
    reduced = _share(answers, kept, sections)
    assert reduced == kept and reduced[0] is kept[0]
    assert all(entry.render_core() in reduced[0].text for entry in answers[small_index].entries)
    rows = reference_delivery(answers, reduced)
    assert rows[small_index]["delivered"]
    assert not rows[1-small_index]["delivered"]
