"""Catalogue-only render reuse returns caller-owned language guidance dicts."""

import gc
import weakref
from functools import lru_cache

import pytest

from core.audit import context


@pytest.fixture(autouse=True)
def owned_caches(monkeypatch):
    monkeypatch.setattr(context, '_patterns_cache', context.BoundedMemo(32))
    monkeypatch.setattr(context, '_pattern_file_cache', context.BoundedMemo(32))
    if hasattr(context, '_pattern_render_cache'):
        monkeypatch.setattr(context, '_pattern_render_cache', context.BoundedMemo(32))
    if hasattr(context, '_matching_trigger_title'):
        original = context._matching_trigger_title
        monkeypatch.setattr(context, '_matching_trigger_title',
                            lru_cache(**original.cache_parameters())(original.__wrapped__))


def test_no_source_guidance_is_mutation_isolated():
    first = context._load_language_patterns('a.c')
    expected = dict(first)
    first['tier1'] = 'consumer edit'
    second = context._load_language_patterns('b.c')
    assert second == expected
    assert first is not second


def test_render_cache_reuses_exact_ordered_content():
    first = context._render_pattern_tiers(['a', 'b'], ['c', 'd'])
    second = context._render_pattern_tiers(['a', 'b'], ['c', 'd'])
    assert first == ('a\n\nb', 'c\nd')
    assert first is second
    assert context._pattern_render_cache.miss_count == 1
    assert context._pattern_render_cache.hit_count == 1
    assert context._render_pattern_tiers(['b', 'a'], ['c', 'd'])[0] == 'b\n\na'


def test_render_cache_is_bounded_and_skips_large_variants():
    for i in range(100):
        context._render_pattern_tiers([f'catalogue {i}'], [])
    assert len(context._pattern_render_cache) == 32
    size = context._PATTERN_RENDER_MAX_CHARS
    before = len(context._pattern_render_cache)
    assert context._render_pattern_tiers(['x' * size, ''], [])[0] == 'x' * size + '\n\n'
    assert len(context._pattern_render_cache) == before
    assert not context._pattern_render_cache.peek((('x' * size, ''), ()), touch=False)[1]


def test_sourceful_guidance_reuses_text_but_not_output_dicts(monkeypatch):
    common = [('A', 'full A', 'summary A', True), ('B', 'full B', 'summary B', True)]
    monkeypatch.setattr(context, '_load_pattern_file', lambda name: common if name == 'common' else [])
    first = context._load_language_patterns('a.c', 'first opaque source')
    second = context._load_language_patterns('b.c', 'different opaque source')
    assert first == second
    assert first is not second
    assert first['tier1'] is second['tier1']
    first['tier1'] = 'consumer edit'
    assert context._load_language_patterns('c.c', 'third source')['tier1'] == 'full A\n\nfull B'


def test_cache_does_not_retain_function_source():
    class Source(str):
        pass

    source = Source('ordinary opaque function source')
    ref = weakref.ref(source)
    result = context._load_language_patterns('a.c', source)
    assert result
    del source
    # These acyclic fixture objects need no scan of unrelated old generations.
    gc.collect(0)
    assert ref() is None


def test_concurrent_no_source_consumers_receive_distinct_dicts():
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: context._load_language_patterns('a.c'), range(8)))
    assert all(result == results[0] for result in results)
    assert len({id(result) for result in results}) == len(results)
    original = results[1]['tier1']
    results[0]['tier1'] = 'consumer edit'
    assert all(result['tier1'] == original for result in results[1:])


def test_trigger_cache_preserves_priority_and_reads_current_values(monkeypatch):
    first = ['first']
    second = ['second']
    monkeypatch.setattr(context, '_TRIGGER_KEYWORDS', {'Alpha': first, 'Alpha Beta': second})
    assert context._match_trigger_keywords('Alpha Beta') is first
    replacement = ['replacement']
    context._TRIGGER_KEYWORDS['Alpha'] = replacement
    assert context._match_trigger_keywords('Alpha Beta') is replacement
    monkeypatch.setattr(context, '_TRIGGER_KEYWORDS', {'Alpha Beta': second, 'Alpha': replacement})
    assert context._match_trigger_keywords('Alpha Beta') is second
    assert context._match_trigger_keywords('unmatched') is None
    context._TRIGGER_KEYWORDS['unmatched'] = first
    assert context._match_trigger_keywords('unmatched') is first


def test_trigger_cache_bounds_and_oversize_bypass(monkeypatch):
    monkeypatch.setattr(context, '_TRIGGER_KEYWORDS', {'Alpha': ['word']})
    for i in range(200):
        assert context._match_trigger_keywords(f'Alpha {i}') == ['word']
    cache = context._matching_trigger_title
    assert cache.cache_info().currsize == 128
    misses = cache.cache_info().misses
    assert context._match_trigger_keywords('Alpha ' + 'x' * 300) == ['word']
    assert cache.cache_info().misses == misses
