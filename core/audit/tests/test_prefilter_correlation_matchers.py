"""Keyword matcher boundaries, bounded cache ownership and hostile CWE input."""

import gc
import weakref
from functools import lru_cache
from types import SimpleNamespace

import pytest

from core.audit import prefilter


@pytest.fixture
def matchers(monkeypatch):
    original = prefilter._family_keyword_search
    owned = lru_cache(**original.cache_parameters())(original.__wrapped__)
    monkeypatch.setattr(prefilter, '_family_keyword_search', owned)
    return owned


@pytest.mark.parametrize(('keyword', 'text', 'expected'), [
    ('free', 'freed', True), ('free', 'unfreed', False),
    ('free', '_free', False), ('free', 'éfree', False),
    ('free', 'é free', True), ('free', '', False),
    ('double free', 'prefixdouble freesuffix', True),
    ('use-after-free', 'prefixuse-after-freesuffix', True),
    ('..', 'prefix..suffix', True), ('a+b', 'a+b', True),
    ('a+b', 'aaab', False),
])
def test_keyword_boundaries_and_literal_metacharacters(matchers, keyword, text, expected):
    assert bool(matchers(frozenset({keyword}))(text)) is expected


def test_keyword_cache_is_bounded_and_reuses_equal_sets(matchers):
    first = frozenset({'free', 'double free'})
    assert matchers(first) is matchers(frozenset(first))
    assert matchers.cache_info().misses == 1
    assert matchers.cache_info().hits == 1
    for i in range(100):
        matchers(frozenset({f'keyword{i}'}))
    info = matchers.cache_info()
    assert 0 < info.maxsize <= 32
    assert info.currsize == info.maxsize
    assert matchers(frozenset())('anything') is None


def test_keyword_cache_does_not_retain_source_text(matchers):
    class Text(str):
        pass

    text = Text('freed pointer')
    ref = weakref.ref(text)
    hit = bool(matchers(frozenset({'free'}))(text))
    assert hit
    del text
    # These acyclic fixture objects need no scan of unrelated old generations.
    gc.collect(0)
    assert ref() is None


def test_family_order_and_changed_keyword_sets_are_preserved(matchers, monkeypatch):
    assert prefilter.family_for_rule('buffer.sql') == 'memory'
    monkeypatch.setitem(prefilter._FAMILY_KEYWORDS, 'custom', frozenset({'first-word'}))
    assert prefilter.evidence_matches_hypothesis('custom', 'prefixfirst-wordsuffix')
    monkeypatch.setitem(prefilter._FAMILY_KEYWORDS, 'custom', frozenset({'second-word'}))
    assert not prefilter.evidence_matches_hypothesis('custom', 'prefixfirst-wordsuffix')
    assert prefilter.evidence_matches_hypothesis('custom', 'second-word')


@pytest.mark.parametrize('text', ['unrelated description', 'buffer overflow'])
def test_oversized_cwe_identifier_falls_back_to_keywords(text):
    result = prefilter.evidence_matches_hypothesis('memory', text, 'CWE-' + '9' * 5000)
    assert result is ('buffer' in text)


def test_builtin_concurrency_checks_do_not_repeat_dynamic_searches(monkeypatch):
    searches = []
    real_re = prefilter.re

    def search(pattern, text):
        searches.append(pattern)
        return real_re.search(pattern, text)

    monkeypatch.setattr(prefilter, 're', SimpleNamespace(search=search, escape=real_re.escape))
    result = prefilter.PrefilterResult(file='f.c', function='f', language='c')
    assert prefilter._is_sink_unreachable_clean(result, 'return 0;', 1)
    assert len(searches) <= 1


@pytest.mark.parametrize('source', ['special_locked();', 'ordinary_work();'])
def test_domain_concurrency_still_uses_prefix_matching(source):
    result = prefilter.PrefilterResult(file='f.c', function='f', language='c')
    clean = prefilter._is_sink_unreachable_clean(
        result, source, 1, extra_concurrency=frozenset({'special_lock'}),
    )
    assert clean is source.startswith('ordinary')
