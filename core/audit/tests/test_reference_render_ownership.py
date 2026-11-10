"""Captured rendering guards apply before every reference-removal stage."""

from dataclasses import replace

import pytest

from core.audit.knowledge_context import dedupe_reference_sections, reference_sections
from core.language_reference import ReferenceContext, lookup


def _reading():
    context = ReferenceContext("c")
    answers = (lookup("division", "", context, entry_id="c.integer-division"),
               lookup("conversion", "integer conversion", context))
    assert all(entry in answers[0].entries for entry in answers[1].entries)
    return answers, reference_sections(answers)


@pytest.mark.parametrize("modified_index", [0, 1], ids=["supplier", "candidate"])
def test_modified_rendering_cannot_donate_or_be_removed(modified_index):
    answers, originals = _reading()
    modified = replace(originals[modified_index], text="Foreign modified reading")
    kept = list(originals)
    kept[modified_index] = modified
    reduced = dedupe_reference_sections(answers, kept, rendered_sections=originals)
    assert reduced == kept
    assert all(after is before for after, before in zip(reduced, kept, strict=True))
    if modified_index == 0:
        assert all(entry.render_core() in reduced[1].text for entry in answers[1].entries)
    else:
        assert all(entry.render_core() in reduced[0].text for entry in answers[0].entries)


def test_matching_owner_record_without_complete_core_tail_cannot_donate():
    answers, originals = _reading()
    modified = replace(originals[0], text="Recorded framing without its rule cores")
    kept = [modified, originals[1]]
    reduced = dedupe_reference_sections(answers, kept, rendered_sections=kept)
    assert reduced == kept and reduced[0] is modified
    assert all(entry.render_core() in reduced[1].text for entry in answers[1].entries)


def test_explicit_empty_owner_map_cannot_authorise_bundle_removal():
    answers, originals = _reading()
    reduced = dedupe_reference_sections(answers, originals, rendered_sections=[])
    assert reduced == originals
    assert all(after is before for after, before in zip(reduced, originals, strict=True))
