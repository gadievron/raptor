"""Audit function windows keep complete row lists and custom-provider order."""

import builtins
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.audit import ptr_lifecycle as pl, resource_bounds as rb
from core.audit.field_census import FunctionSpan
from core.source.lines import split_lines
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("start,end", [(1, 3), (1000, 1003), (2500, 2502), (2502, 2510), (0, 3), (3, 2)])
def test_alias_window_matches_eager_slice(start, end):
    source = "padding\r\n" * 2500 + "\n\r\n"
    assert pl._alias_segment(source, FunctionSpan("owner", start, end)) == split_lines(source)[start - 1:end]


def test_alias_span_adapter_keeps_split_before_coordinate_access():
    seen = []

    class Span:
        @property
        def start(self):
            seen.append("start")
            return 1

        @property
        def end(self):
            seen.append("end")
            return 2

    def split(source):
        seen.append("split")
        return ["first", ""]

    view = module_function_view(pl, bindings={"split_lines": split})
    assert view._alias_segment("padding\n" * 2500, Span()) == ["first", ""]
    assert seen == ["split", "start", "end"]


def test_alias_native_span_keeps_replaced_splitter():
    seen = []

    def split(source):
        seen.append(source)
        return ["first", "", "last"]

    source = "padding\n" * 2500
    view = module_function_view(pl, bindings={"split_lines": split})
    assert view._alias_segment(source, FunctionSpan("owner", 1, 2)) == ["first", ""]
    assert seen == [source]


def bounds_view(span, captured, *, splitter=None):
    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "fail_open_lang" and level == 1:
            return SimpleNamespace(is_binary_row=lambda path: False, language_for_path=lambda path: "c",
                                   c_function_span=lambda *args, **kwargs: span)
        return builtins.__import__(name, globals, locals, fromlist, level)

    def enumerate_sites(rows, start, *args, **kwargs):
        captured.append((rows, start))
        return []

    bindings = {"_enumerate_sites": enumerate_sites, "_insert_vocabulary": lambda *args: {},
                "_alloc_vocabulary": lambda *args: {}, "_candidate_verbs_from_hypothesis": lambda *args: []}
    if splitter is not None:
        bindings["split_lines"] = splitter
    return module_function_view(rb, bindings=bindings, import_hook=import_local)


@pytest.mark.parametrize("span", [(1, 3), (2499, 2503), (2502, 2510), (0, 3), (3, 2), None])
def test_bounds_check_passes_exact_window_rows_to_enumeration(span):
    source = "padding\r\n" * 2500 + "\n\r\n"
    captured = []
    view = bounds_view(span, captured)
    result = view.run_resource_bounds_check(Path("/nonexistent"), "owner.c", "owner", "",
                                            source_texts={"owner.c": source})
    rows = split_lines(source)
    assert captured == [(rows[span[0] - 1:span[1]], span[0]) if span else (rows, 1)]
    assert result.outcome == "inconclusive"


def test_bounds_span_adapter_keeps_split_before_truth_and_indexing():
    seen = []

    class Span:
        def __bool__(self):
            seen.append("truth")
            return True

        def __getitem__(self, index):
            seen.append(index)
            return (1, 2)[index]

    def split(source):
        seen.append("split")
        return ["first", "", "last"]

    captured = []
    view = bounds_view(Span(), captured, splitter=split)
    view.run_resource_bounds_check(Path("/nonexistent"), "owner.c", "owner", "",
                                   source_texts={"owner.c": "padding\n" * 2500})
    assert seen == ["split", "truth", 0, 1, 0]
    assert captured == [(["first", ""], 1)]
