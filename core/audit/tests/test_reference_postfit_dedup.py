"""Post-fit sharing removes only complete reading already retained elsewhere."""

from dataclasses import replace

import pytest

from core.audit.context import format_context_for_prompt
from core.audit.knowledge_context import reference_delivery, reference_sections
from core.language_reference import ReferenceContext, lookup
from core.llm.prompt_budget import PromptSection, fit_to_budget


def _answers():
    context = ReferenceContext("c")
    division = lookup("division-owned", "", context, entry_id="c.integer-division")
    conversion = lookup("conversion-owned", "integer conversion", context)
    assert conversion.entries and all(entry in division.entries for entry in conversion.entries)
    assert len(conversion.entries) < len(division.entries)
    return division, conversion


@pytest.mark.parametrize("budget", [100_000, 0], ids=["ample", "unlimited"])
@pytest.mark.parametrize("superset_first", [True, False])
def test_actual_prompt_retains_one_complete_core_for_shared_reading(budget, superset_first):
    division, conversion = _answers()
    answers = (division, conversion) if superset_first else (conversion, division)
    source = "unsigned short f(unsigned n) { return n; }"
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source, "language_reference_answers": answers}
    prompt = format_context_for_prompt(ctx, budget_limit=budget)
    assert source in prompt
    for entry in division.entries:
        assert prompt.count(entry.render_core()) == 1
        assert entry.conditions and entry.citations and entry.required_target_facts
    rows = ctx["language_reference_delivery"]
    assert {row["request_id"] for row in rows} == {division.request_id, conversion.request_id}
    assert all(row["delivered"] and row["reason"] == "delivered" for row in rows)
    assert all(row["missing_facts"] == ["language edition"] for row in rows)
    assert "Target language edition is unknown" in prompt


def test_postfit_dedup_preserves_small_fallback_when_superset_was_shed():
    from core.audit.knowledge_context import dedupe_reference_sections

    division, conversion = _answers()
    conversion = replace(conversion, selection_kind="entry_id")
    division = replace(division, selection_kind="topic")
    answers = (conversion, division)
    sections = reference_sections(answers)
    assert sections[0].token_estimate < sections[1].token_estimate
    kept, shed = fit_to_budget(sections, budget_tokens=sections[0].token_estimate)
    assert kept == [sections[0]] and shed == [sections[1]]
    before = tuple(kept)
    reduced = dedupe_reference_sections(answers, kept)
    assert tuple(kept) == before and reduced == kept
    assert reduced[0] is sections[0]
    assert all(entry.render_core() in reduced[0].text for entry in conversion.entries)
    assert division.entries[-1].render_core() not in reduced[0].text
    rows = reference_delivery(answers, reduced)
    assert rows[0]["delivered"]
    assert not rows[1]["delivered"] and rows[1]["reason"] == "reference_too_large"


@pytest.mark.parametrize("difference", ["pack", "applicability", "content"])
def test_postfit_dedup_preserves_incompatible_whole_sections(difference):
    from core.audit.knowledge_context import dedupe_reference_sections

    division, conversion = _answers()
    if difference == "pack":
        conversion = replace(conversion, pack_version="c-integers-other")
    elif difference == "applicability":
        conversion = replace(conversion, missing_facts=("language edition", "configured integer range"))
    else:
        original = conversion.entries[0]
        changed = replace(original, rule=original.rule + " A distinct reviewed condition.")
        assert (changed.entry_id, changed.version) == (original.entry_id, original.version)
        conversion = replace(conversion, entries=(changed,))
    answers = (division, conversion)
    sections = reference_sections(answers)
    kept, shed = fit_to_budget(sections, budget_tokens=sum(s.token_estimate for s in sections))
    assert kept == sections and not shed
    before = tuple(kept)
    reduced = dedupe_reference_sections(answers, kept)
    assert tuple(kept) == before and reduced == kept
    assert all(after is prior for after, prior in zip(reduced, kept, strict=True))
    assert all(row["delivered"] for row in reference_delivery(answers, reduced))


def test_postfit_dedup_preserves_shared_subset_label_with_an_incompatible_pack_alias():
    from core.audit.knowledge_context import dedupe_reference_sections

    division, conversion = _answers()
    other_pack_alias = replace(conversion, request_id="other-pack-owned", pack_version="c-integers-other")
    answers = (division, conversion, other_pack_alias)
    sections = reference_sections(answers)
    assert len(sections) == 2
    kept, shed = fit_to_budget(sections, budget_tokens=sum(s.token_estimate for s in sections))
    assert kept == sections and not shed
    before_rows = reference_delivery(answers, kept)
    assert all(row["delivered"] for row in before_rows)
    reduced = dedupe_reference_sections(answers, kept)
    assert reduced == kept
    assert reference_delivery(answers, reduced) == before_rows
    assert all(after is prior for after, prior in zip(reduced, kept, strict=True))


def test_postfit_dedup_keeps_maximal_chain_and_nonreference_sections_unchanged():
    from core.audit.knowledge_context import dedupe_reference_sections

    context = ReferenceContext("c")
    small = lookup("small", "", context, entry_id="c.integer-promotion")
    middle = lookup("middle", "", context, entry_id="c.integer-usual-conversions")
    large = lookup("large", "", context, entry_id="c.integer-division")
    assert len(small.entries) < len(middle.entries) < len(large.entries)
    assert all(entry in middle.entries for entry in small.entries)
    assert all(entry in large.entries for entry in middle.entries)
    answers = (small, middle, large)
    references = reference_sections(answers)
    source = PromptSection("source", "int f(int n) { return n; }", 0)
    evidence = PromptSection("mechanical_evidence", "Scoped mechanical observation, not a verdict.", 0)
    sections = [source, *references, evidence]
    kept, shed = fit_to_budget(sections, budget_tokens=sum(s.token_estimate for s in sections))
    assert kept == sections and not shed
    before = tuple(kept)
    reduced = dedupe_reference_sections(answers, kept)
    assert tuple(kept) == before
    assert reduced == [source, references[-1], evidence]
    assert reduced[0] is source and reduced[-1] is evidence
    assert reduced[1] is references[-1]
    assert sum(s.token_estimate for s in reduced) < sum(s.token_estimate for s in kept)
    assert sum(s.token_estimate for s in kept) - sum(s.token_estimate for s in reduced) == sum(
        s.token_estimate for s in references[:-1])
    for entry in large.entries:
        assert reduced[1].text.count(entry.render_core()) == 1
        assert entry.conditions and entry.citations and entry.required_target_facts
    assert all(row["delivered"] for row in reference_delivery(answers, reduced))


def test_postfit_dedup_does_not_restore_shed_reading_or_original_elided_source():
    from core.audit.knowledge_context import dedupe_reference_sections
    from core.llm.prompt_budget import fit_to_budget_report

    answers = _answers()
    references = reference_sections(answers)
    source = PromptSection("source", "x" * 20_000, 0)
    report = fit_to_budget_report([source, *references], 1000, elide_priority0=True)
    assert report.elisions and all(item.label == "source" for item in report.elisions)
    assert report.shed == references
    assert len(report.kept) == 1 and report.kept[0].label == "source"
    assert report.kept[0].text != source.text
    reduced = dedupe_reference_sections(answers, report.kept)
    assert reduced == report.kept and reduced[0] is report.kept[0]
    assert not any(row["delivered"] for row in reference_delivery(answers, reduced))
