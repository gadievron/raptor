"""List windows preserve row cardinality as well as joined source text."""

import random

import pytest

from core.source import lines
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("tail", [
    pytest.param("", id="empty"), pytest.param("\n", id="lf"),
    pytest.param("\r", id="cr"), pytest.param("\r\n", id="crlf"),
    pytest.param("\n\n", id="blank"), pytest.param("\r\r\n", id="double-cr"),
    pytest.param("a\n\n\rb\v\u2028\n\r", id="mixed"),
])
def test_windows_preserve_final_and_interior_empty_rows(tail):
    source = "padding\n" * 2500 + tail
    rows = lines.split_lines(source)
    for start in (1, 2499, 2500, 2501, 2502, 2503, 2505):
        for end in (start, start + 1, start + 5):
            assert lines.slice_source_lines(source, start, end) == rows[start - 1:end], (start, end, tail)


def test_generated_native_windows_match_canonical_list_slices():
    randomizer = random.Random(813)
    alphabet = ["", "alpha", "\r", "\r\r", "λ\v\f\x85\u2028\u2029", "z" * 90]
    for _ in range(200):
        source = "padding\n" * 2200 + "\n".join(randomizer.choice(alphabet) for _ in range(60))
        rows = lines.split_lines(source)
        for _ in range(12):
            start = randomizer.randrange(1, len(rows) + 10)
            end = start + randomizer.randrange(30)
            assert lines.slice_source_lines(source, start, end) == rows[start - 1:end], (start, end)


@pytest.mark.parametrize("start,end", [(0, 1), (-1, 2), (3, 2), (True, 4), (2, True)])
def test_invalid_or_adapter_bounds_keep_slice_lines_contract(start, end):
    text = "padding\n" * 2500
    assert lines.slice_source_lines(text, start, end) == lines.slice_lines(lines.split_lines(text), start, end)


def test_string_adapter_keeps_its_split():
    calls = []

    class Source(str):
        def split(self, separator):
            calls.append(separator)
            return ["first", "", "last"]

    assert lines.slice_source_lines(Source("ignored"), 1, 2) == ["first", ""]
    assert calls == ["\n"]


def test_adapter_replaced_splitter_stays_authoritative():
    seen = []

    def split(text):
        seen.append(text)
        return ["first", "", "last"]

    class Source(str):
        pass

    text = Source("padding\n" * 2500)
    view = module_function_view(lines, bindings={"split_lines": split})
    assert view.slice_source_lines(text, 1, 2) == ["first", ""]
    assert seen == [text]


def test_native_window_does_not_split_entire_source():
    import sys

    if sys.getprofile() is not None:
        pytest.skip("profiling hook already owned")
    source = "padding\n" * 10000
    whole_splits = []

    def observe(frame, event, arg):
        if event == "call" and frame.f_code is lines.split_lines.__code__ and frame.f_locals.get("text") is source:
            whole_splits.append(source)

    try:
        sys.setprofile(observe)
        selected = lines.slice_source_lines(source, 3, 5)
    finally:
        sys.setprofile(None)
    assert selected == ["padding"] * 3
    assert whole_splits == []


def test_native_window_keeps_canonical_split_semantics():
    def unwanted(text):
        pytest.fail("native window delegated to a replaced shared splitter")

    view = module_function_view(lines, bindings={"split_lines": unwanted})
    assert view.slice_source_lines("padding\n" * 2500, 2, 3) == ["padding", "padding"]


@pytest.mark.parametrize("start,end", [(1, 10000), (1, 5000), (2000, 3000), (1000, 1100), (1800, 2200)])
def test_broad_windows_keep_native_split_results(start, end):
    source = "padding\r\n" * 2500 + "\r\n"
    assert lines.slice_source_lines(source, start, end) == lines.split_lines(source)[start - 1:end]
