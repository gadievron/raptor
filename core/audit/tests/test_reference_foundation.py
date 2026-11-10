"""Initial reference cores remain conditional reading, never target facts."""

from dataclasses import replace

import pytest

from core.audit import reference_foundation as foundation
from core.language_reference import ReferenceAnswer, c_integer


def test_c_foundation_preserves_complete_current_rules_and_opaque_identity():
    answer, = foundation.foundation_answers("c", request_id="opaque:initial:unit")
    assert answer.request_id == "opaque:initial:unit"
    assert answer.status == "needs_target_facts"
    assert answer.missing_facts == ("language edition",)
    assert [entry.entry_id for entry in answer.entries] == ["c.integer-promotion", "c.integer-conversion"]
    current = {entry.entry_id: entry for entry in c_integer.ENTRIES}
    assert all(entry == current[entry.entry_id] for entry in answer.entries)
    assert all(entry.rule and entry.conditions and entry.citations and entry.required_target_facts for entry in answer.entries)
    assert "represents every value" in answer.entries[0].render_core()
    assert "implementation-defined signal" in answer.entries[1].render_core()
    assert "64-bit" not in answer.reason


@pytest.mark.parametrize("language", [None, "", "cpp", "C", "rust", "binary", {}])
def test_unknown_or_non_c_language_has_no_c_foundation(language):
    assert foundation.foundation_answers(language, request_id="owned") == ()


def test_binary_flag_prevents_c_foundation_even_with_c_hint():
    assert foundation.foundation_answers("c", request_id="owned", binary=True) == ()


@pytest.mark.parametrize("request_id", [None, 1, "", "x" * 129, "line\nbreak", "nul\x00id"])
def test_invalid_pipeline_identity_is_refused(request_id):
    with pytest.raises(ValueError):
        foundation.foundation_answers("c", request_id=request_id)


def test_exact_identity_limit_is_preserved_without_parsing():
    answer, = foundation.foundation_answers("c", request_id="x" * 128)
    assert answer.request_id == "x" * 128


def test_changed_current_rule_is_used_without_a_content_cache(monkeypatch):
    changed = tuple(replace(entry, rule=entry.rule + " Reviewed clarification.")
                    if entry.entry_id == "c.integer-promotion" else entry for entry in c_integer.ENTRIES)
    monkeypatch.setattr(c_integer, "ENTRIES", changed)
    answer, = foundation.foundation_answers("c", request_id="owned")
    assert answer.status == "needs_target_facts"
    assert answer.entries[0].rule.endswith("Reviewed clarification.")


def test_prerequisites_are_included_once_before_their_dependent_rule(monkeypatch):
    monkeypatch.setattr(c_integer, "ENTRIES", tuple(
        replace(entry, prerequisites=("c.integer-conversion",))
        if entry.entry_id == "c.integer-promotion" else entry for entry in c_integer.ENTRIES))
    answer, = foundation.foundation_answers("c", request_id="owned")
    assert [entry.entry_id for entry in answer.entries] == ["c.integer-conversion", "c.integer-promotion"]


@pytest.mark.parametrize("change", ["missing", "conflict", "cycle", "unknown-prerequisite"])
def test_unavailable_or_conflicting_pack_has_one_explicit_empty_result(monkeypatch, change):
    entries = c_integer.ENTRIES
    promotion = next(entry for entry in entries if entry.entry_id == "c.integer-promotion")
    if change == "missing":
        updated = tuple(entry for entry in entries if entry.entry_id != promotion.entry_id)
    elif change == "conflict":
        updated = (*entries, replace(promotion, rule="Conflicting rule"))
    else:
        prerequisite = promotion.entry_id if change == "cycle" else "c.missing-prerequisite"
        updated = tuple(replace(entry, prerequisites=(prerequisite,))
                        if entry.entry_id == promotion.entry_id else entry for entry in entries)
    monkeypatch.setattr(c_integer, "ENTRIES", updated)
    answer, = foundation.foundation_answers("c", request_id="owned")
    assert answer == ReferenceAnswer("owned", "unsupported", reason="initial_reference_foundation_unavailable")


def test_conflicting_resolver_bundles_are_not_silently_deduplicated(monkeypatch):
    original = foundation.lookup
    def inconsistent(request_id, topic, context, *, entry_id):
        answer = original(request_id, topic, context, entry_id=entry_id)
        if entry_id == "c.integer-conversion":
            promotion = next(entry for entry in c_integer.ENTRIES if entry.entry_id == "c.integer-promotion")
            return replace(answer, entries=(*answer.entries, replace(promotion, version=promotion.version+1)))
        return answer
    monkeypatch.setattr(foundation, "lookup", inconsistent)
    answer, = foundation.foundation_answers("c", request_id="owned")
    assert answer.status == "unsupported" and not answer.entries


def test_oversized_current_pack_is_not_traversed(monkeypatch):
    monkeypatch.setattr(c_integer, "ENTRIES", c_integer.ENTRIES * 257)
    answer, = foundation.foundation_answers("c", request_id="owned")
    assert answer.status == "unsupported" and not answer.entries


def test_resolver_answer_entry_cap_is_not_truncated_into_a_partial_foundation(monkeypatch):
    original = foundation.lookup
    def oversized(request_id, topic, context, *, entry_id):
        answer = original(request_id, topic, context, entry_id=entry_id)
        return replace(answer, entries=answer.entries * 33)
    monkeypatch.setattr(foundation, "lookup", oversized)
    answer, = foundation.foundation_answers("c", request_id="owned")
    assert answer.status == "unsupported" and not answer.entries
