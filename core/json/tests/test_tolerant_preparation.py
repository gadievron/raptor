"""Absent recovery markers avoid scans without changing adapter behaviour."""

from contextlib import contextmanager
import sys
from types import SimpleNamespace

import pytest

from core.json import tolerant
from core.testing.module_views import module_function_view


@contextmanager
def fence_work(source):
    if sys.getprofile() is not None:
        pytest.skip("profiling hook already owned")
    counts = {"split": 0, "match": 0}

    def observe(frame, event, arg):
        if event != "c_call":
            return
        owner = getattr(arg, "__self__", None)
        name = getattr(arg, "__name__", None)
        if owner is source and name == "split":
            counts["split"] += 1
        if owner is tolerant._FENCE_LINE_RE and name == "match":
            counts["match"] += 1

    try:
        sys.setprofile(observe)
        yield counts
    finally:
        sys.setprofile(None)


def test_fence_free_native_text_does_not_split_or_match_lines():
    source = "ordinary response\n" * 2000
    with fence_work(source) as counts:
        assert tolerant._extract_fence(source) == (None, None)
    assert counts == {"split": 0, "match": 0}


@pytest.mark.parametrize("function", [
    "_fix_single_quotes", "_fix_python_literals", "_fix_trailing_commas",
])
def test_marker_free_native_fixups_keep_the_original_string(function):
    source = "unchanged payload\n" * 2000
    assert getattr(tolerant, function)(source) is source


@pytest.mark.parametrize("function,source,expected", [
    pytest.param("_fix_single_quotes", "{'ok': 1}", '{"ok": 1}', id="quotes"),
    pytest.param("_fix_python_literals", '{"ok": True}', '{"ok": true}', id="literal"),
    pytest.param("_fix_trailing_commas", '{"ok": 1, }', '{"ok": 1}', id="comma"),
])
def test_present_markers_still_reach_the_transform(function, source, expected):
    assert getattr(tolerant, function)(source) == expected


@pytest.mark.parametrize("source", ["ordinary response", "only { opening", "only } closing"])
def test_missing_pair_delimiter_retains_empty_span(source):
    assert tolerant._extract_delim_span(source, "{", "}") == (None, 0, 0)


def test_balanced_spans_still_keep_positions_and_last_object():
    assert tolerant._extract_delim_span('before {"a": 1} then {"b": 2} after', "{", "}") == (
        '{"b": 2}', 21, 6,
    )


def test_split_adapter_is_authoritative_without_literal_fence_markers():
    seen = []

    class Source(str):
        def split(self, separator):
            seen.append(separator)
            return ["```json", '{"ok": 1}', "```"]

        def __contains__(self, item):
            pytest.fail("native marker admission inspected a source adapter")

    assert tolerant._extract_fence(Source("adapter response")) == ("json", '{"ok": 1}')
    assert seen == ["\n"]


def test_foreign_fence_matcher_is_not_pruned_by_native_markers():
    seen = []

    class Matcher:
        def match(self, line):
            seen.append(line)
            if line == "START":
                return SimpleNamespace(group=lambda key: {"delim": "END", "lang": "owned"}[key])
            return None

    view = module_function_view(tolerant, bindings={"_FENCE_LINE_RE": Matcher()})
    assert view._extract_fence('START\n{"ok": 1}\nEND') == ("owned", '{"ok": 1}')
    assert seen == ["START"]


@pytest.mark.parametrize("function", [
    "_fix_single_quotes", "_fix_python_literals", "_fix_trailing_commas",
])
def test_source_adapters_do_not_take_literal_absence_paths(function):
    class Source(str):
        def __contains__(self, item):
            pytest.fail("native marker admission inspected a source adapter")

    assert getattr(tolerant, function)(Source("unchanged payload")) == "unchanged payload"


@pytest.mark.parametrize("function", [
    "_fix_single_quotes", "_fix_python_literals", "_fix_trailing_commas",
])
def test_custom_length_keeps_the_original_scanner_path(function):
    view = module_function_view(tolerant, bindings={"len": lambda value: 0})
    assert getattr(view, function)("unchanged payload") == ""


def test_custom_range_failure_is_not_hidden_by_delimiter_admission():
    reached = []

    def fail(count):
        reached.append(count)
        raise ValueError("owned range failure")

    view = module_function_view(tolerant, bindings={"range": fail})
    with pytest.raises(ValueError, match="owned range failure"):
        view._extract_delim_span("plain", "{", "}")
    assert reached == [5]


def test_delimiter_adapters_keep_their_equality_semantics():
    class Opening(str):
        def __eq__(self, other):
            return other == "{"

    class Closing(str):
        def __eq__(self, other):
            return other == "}"

    assert tolerant._extract_delim_span("before {}", Opening("A"), Closing("Z")) == ("{}", 7, 0)
