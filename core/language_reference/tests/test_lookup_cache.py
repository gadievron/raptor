"""Shared reading computation keeps request ownership and pack changes separate."""

import pytest

from core.language_reference import ReferenceContext, lookup
from core.language_reference import c_integer, resolver


@pytest.fixture(autouse=True)
def isolated_lookup_cache():
    cached = getattr(resolver, "_lookup_cached", None)
    if cached is not None:
        cached.cache_clear()
    try:
        yield
    finally:
        if cached is not None:
            cached.cache_clear()


def test_equivalent_requests_share_computation_but_keep_separate_request_ids(monkeypatch):
    original = resolver._tokens
    titles = {entry.title for entry in c_integer.ENTRIES}
    ranked = []
    def counted(text):
        if text in titles:
            ranked.append(text)
        return original(text)
    monkeypatch.setattr(resolver, "_tokens", counted)
    first = lookup("unit-a-request", "division", ReferenceContext("c"))
    first_work = len(ranked)
    assert first_work > 0 and first.entries
    second = lookup("unit-b-request", "DIVISION!!!", ReferenceContext("c"))
    assert first.request_id == "unit-a-request" and second.request_id == "unit-b-request"
    assert first.entries == second.entries and first.status == second.status
    assert len(ranked) == first_work


def test_warm_result_does_not_cross_language_or_edition_boundaries():
    contexts = [ReferenceContext("c", "c11"), ReferenceContext("c"),
                ReferenceContext("c", "c23"), ReferenceContext("cpp", "c++11")]
    answers = [lookup(str(index), "", context, entry_id="c.integer-conversion")
               for index, context in enumerate(contexts)]
    assert [answer.status for answer in answers] == ["answered", "needs_target_facts", "unsupported", "unsupported"]
    assert answers[1].missing_facts == ("language edition",)
    assert not answers[2].entries and not answers[3].entries
    assert [answer.request_id for answer in answers] == ["0", "1", "2", "3"]


@pytest.mark.parametrize("field,value", [("rule", "A reviewed replacement rule."), ("version", 2)])
def test_pack_content_change_invalidates_positive_results(monkeypatch, field, value):
    from dataclasses import replace
    old = lookup("before", "", ReferenceContext("c"), entry_id="c.integer-conversion")
    monkeypatch.setattr(c_integer, "ENTRIES", tuple(replace(entry, **{field: value})
        if entry.entry_id == "c.integer-conversion" else entry for entry in c_integer.ENTRIES))
    new = lookup("after", "", ReferenceContext("c"), entry_id="c.integer-conversion")
    assert new.request_id == "after" and old.request_id == "before"
    assert getattr(new.entries[-1], field) == value
    assert old.entries != new.entries


def test_prerequisite_change_invalidates_even_when_rendered_core_is_unchanged(monkeypatch):
    from dataclasses import replace
    old = lookup("before", "", ReferenceContext("c"), entry_id="c.integer-conversion")
    monkeypatch.setattr(c_integer, "ENTRIES", tuple(replace(entry, prerequisites=("c.integer-promotion",))
        if entry.entry_id == "c.integer-conversion" else entry for entry in c_integer.ENTRIES))
    new = lookup("after", "", ReferenceContext("c"), entry_id="c.integer-conversion")
    assert old.entries[-1].render_core() == new.entries[-1].render_core()
    assert [entry.entry_id for entry in old.entries] == ["c.integer-conversion"]
    assert [entry.entry_id for entry in new.entries] == ["c.integer-promotion", "c.integer-conversion"]


@pytest.mark.parametrize("field", ["topics", "summary"])
def test_ranking_metadata_invalidates_negative_result_without_render_changes(monkeypatch, field):
    from dataclasses import replace
    assert lookup("before", "cachemetakey", ReferenceContext("c")).status == "unsupported"
    original = next(entry for entry in c_integer.ENTRIES if entry.entry_id == "c.integer-conversion")
    value = (*original.topics, "cachemetakey") if field == "topics" else original.summary + " cachemetakey"
    changed = replace(original, **{field: value})
    assert changed.render_core() == original.render_core()
    monkeypatch.setattr(c_integer, "ENTRIES", tuple(changed if entry == original else entry for entry in c_integer.ENTRIES))
    answer = lookup("after", "CACHEMETAKEY!", ReferenceContext("c"))
    assert answer.status == "needs_target_facts"
    assert [entry.entry_id for entry in answer.entries] == ["c.integer-conversion"]


def test_new_pack_entry_invalidates_unsupported_exact_id(monkeypatch):
    from dataclasses import replace
    assert lookup("before", "", ReferenceContext("c"), entry_id="c.future").status == "unsupported"
    added = replace(c_integer.ENTRIES[0], entry_id="c.future")
    monkeypatch.setattr(c_integer, "ENTRIES", (*c_integer.ENTRIES, added))
    answer = lookup("after", "", ReferenceContext("c"), entry_id="c.future")
    assert answer.request_id == "after" and answer.entries == (added,)


def test_pack_label_is_part_of_cache_context(monkeypatch):
    from functools import partial
    first = lookup("before", "", ReferenceContext("c"), entry_id="c.integer-conversion")
    before = resolver._lookup_cached.cache_info()
    monkeypatch.setattr(resolver, "ReferenceAnswer", partial(resolver.ReferenceAnswer, pack_version="c-integers-next"))
    second = lookup("after", "", ReferenceContext("c"), entry_id="c.integer-conversion")
    assert second.entries == first.entries
    assert first.pack_version == "c-integers-1" and second.pack_version == "c-integers-next"
    assert resolver._lookup_cached.cache_info().misses == before.misses + 1


def test_topic_validation_precedes_warm_exact_id_lookup():
    assert lookup("warm", "", ReferenceContext("c"), entry_id="c.integer-conversion").entries
    before = resolver._lookup_cached.cache_info()
    for topic in ("x" * 513, None):
        answer = lookup("invalid", topic, ReferenceContext("c"), entry_id="c.integer-conversion")
        assert answer.status == "unsupported" and not answer.entries
    assert resolver._lookup_cached.cache_info() == before


def test_empty_exact_id_is_not_treated_as_topic_lookup():
    assert lookup("topic", "conversion", ReferenceContext("c")).entries
    answer = lookup("id", "conversion", ReferenceContext("c"), entry_id="")
    assert answer.request_id == "id" and answer.status == "unsupported" and not answer.entries


def test_cache_retention_is_bounded_for_many_unsupported_topics():
    for index in range(200):
        assert lookup(str(index), f"unreviewed{index}", ReferenceContext("c")).status == "unsupported"
    info = resolver._lookup_cached.cache_info()
    assert info.maxsize == 128 and info.currsize <= info.maxsize


def test_concurrent_callers_receive_their_own_envelopes():
    from concurrent.futures import ThreadPoolExecutor
    def request(index):
        return lookup(f"unit-{index}", "division", ReferenceContext("c"))
    with ThreadPoolExecutor(max_workers=4) as pool:
        answers = list(pool.map(request, range(32)))
    assert all(answer.request_id == f"unit-{index}" for index, answer in enumerate(answers))
    assert all(answer.entries == answers[0].entries for answer in answers)


@pytest.mark.parametrize("pack", [[], (None,) * 257])
def test_unbounded_or_mutable_pack_is_not_admitted_to_cache(monkeypatch, pack):
    monkeypatch.setattr(c_integer, "ENTRIES", pack)
    answer = lookup("owned", "division", ReferenceContext("c"))
    assert answer.status == "unsupported" and not answer.entries
    assert resolver._lookup_cached.cache_info().currsize == 0


def test_mutable_entry_contents_are_refused_instead_of_cached(monkeypatch):
    from dataclasses import replace
    changed = replace(c_integer.ENTRIES[0], topics=["conversion"])
    monkeypatch.setattr(c_integer, "ENTRIES", (changed,))
    answer = lookup("owned", "conversion", ReferenceContext("c"))
    assert answer.status == "unsupported" and not answer.entries
    assert resolver._lookup_cached.cache_info().currsize == 0
