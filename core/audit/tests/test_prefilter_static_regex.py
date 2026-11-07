"""Lazy, fixed prefilter matchers do not cache source text or grow with input."""

import gc
import weakref
from functools import cached_property

import pytest

from core.audit import prefilter


@pytest.fixture
def searches(monkeypatch):
    owned = prefilter._StaticSearches()
    monkeypatch.setattr(prefilter, "_STATIC_SEARCHES", owned)
    return owned


def test_matchers_are_lazy_and_reused_across_source_texts(searches):
    assert vars(searches) == {}
    matcher = searches.array_access
    for i in range(100):
        source = f"value{i}[0]"
        match = matcher(source)
        assert match.group(0) == f"value{i}["
        assert match.string is source
    assert searches.array_access is matcher
    assert list(vars(searches)) == ["array_access"]


def test_case_insensitive_match_keeps_captures_and_span(searches):
    match = searches.c_sql_format("SeLeCt %s")
    assert match.group(0) == "SeLeCt %s"
    assert match.groups() == ("SeLeCt",)
    assert match.span() == (0, 9)


def test_missing_names_do_not_expand_fixed_catalog(searches):
    names = [name for name, value in vars(prefilter._StaticSearches).items()
             if isinstance(value, cached_property)]
    for name in names:
        assert callable(getattr(searches, name))
    assert set(vars(searches)) == set(names)
    for i in range(100):
        with pytest.raises(AttributeError):
            getattr(searches, f"unconfigured_{i}")
    assert set(vars(searches)) == set(names)


def test_source_text_is_not_retained_by_matchers(searches):
    class Source(str):
        pass

    source = Source("strcpy(dst, src);")
    ref = weakref.ref(source)
    assert searches.strcpy_call(source) is not None
    del source
    # These acyclic fixture objects need no scan of unrelated old generations.
    gc.collect(0)
    assert ref() is None
    assert list(vars(searches)) == ["strcpy_call"]
