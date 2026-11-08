"""Bounded preparation retains native results and eager adapter operations."""

import builtins
import re
import sys
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from core.audit import fail_open_verify as verify, release_order as release
from core.source.lines import iter_source_lines, split_lines
from core.testing import requires_ts
from core.testing.module_views import module_function_view


@contextmanager
def whole_splits(source):
    if sys.getprofile() is not None:
        pytest.skip("profiling hook already owned")
    seen = []

    def observe(frame, event, arg):
        if (event == "call" and frame.f_code is split_lines.__code__
                and frame.f_locals.get("text") is source):
            seen.append(source)

    try:
        sys.setprofile(observe)
        yield seen
    finally:
        sys.setprofile(None)


def release_view(span, *, bindings=None):
    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "fail_open_lang" and level == 1:
            return SimpleNamespace(c_function_span=lambda *args, **kwargs: span)
        return builtins.__import__(name, globals, locals, fromlist, level)

    return module_function_view(release, bindings=bindings, import_hook=import_local)


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("span", [(2, 4), (2000, 2004), (2001, 2001), (2100, 2105)])
def test_release_segments_match_whole_source_slices_without_whole_splits(newline, span):
    source = ("// padding\v\u2028\n" * 2000 + "\nint owner(void) {\n return 1;\n}\n\r").replace("\n", newline)
    expected = split_lines(source)[span[0] - 1:span[1]], span[0]
    with whole_splits(source) as seen:
        assert release_view(span)._function_segment(source, "owner", "c") == expected
    assert seen == []


@requires_ts("c")
def test_release_segment_uses_actual_parser_coordinates():
    source = "// padding\n" * 2000 + "int owner(void) {\n return 1;\n}\n"
    with whole_splits(source) as seen:
        assert release._function_segment(source, "owner", "c") == (
            ["int owner(void) {", " return 1;", "}"], 2001,
        )
    assert seen == []


@pytest.mark.parametrize("span", [None, (), (0, 2), (-2, 3), (4, 2), (True, 4), [2, 4]])
def test_release_noncanonical_spans_keep_eager_slice_behaviour(span):
    source = "// padding\n" * 2000
    rows = split_lines(source)
    expected = (rows[span[0] - 1:span[1]], span[0]) if span else (rows, 1)
    with whole_splits(source) as seen:
        assert release_view(span)._function_segment(source, "owner", "c") == expected
    assert len(seen) == 1


def test_release_custom_splitter_runs_before_adapter_coordinates():
    events = []

    class Span:
        def __bool__(self):
            events.append("truth")
            return True

        def __getitem__(self, index):
            events.append(index)
            return (1, 2)[index]

    def split(source):
        events.append("split")
        return ["adapter", "rows", "unused"]

    view = release_view(Span(), bindings={"split_lines": split})
    assert view._function_segment("// padding\n" * 2000, "owner", "c") == (["adapter", "rows"], 1)
    assert events == ["split", "truth", 0, 1, 0]


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("gap", [0, 1, 2, 3])
@pytest.mark.parametrize("at_end", [False, True])
def test_same_file_wur_keeps_exact_three_row_lookbehind(newline, gap, at_end):
    declaration = "__must_check\n" + "// intervening\n" * gap + "int reviewed(void);\n"
    source = ("// padding\v\u2028\n" * 2000 + declaration if at_end
              else declaration + "// padding\v\u2028\n" * 2000).replace("\n", newline)
    with whole_splits(source) as seen:
        assert verify._same_file_wur(source, "reviewed") is (gap <= 1)
    assert seen == []


def test_same_file_wur_stops_after_first_witness():
    consumed = []

    def rows(source):
        for row in iter_source_lines(source):
            consumed.append(row)
            yield row

    view = module_function_view(verify, bindings={"iter_source_lines": rows})
    source = "__must_check\n\nint reviewed(void);\n" + "// padding\n" * 2000
    assert view._same_file_wur(source, "reviewed") is True
    assert consumed == ["__must_check", "", "int reviewed(void);"]


def test_same_file_wur_checks_later_declarations_after_a_miss():
    source = ("int reviewed(void);\n" + "// padding\n" * 2000
              + "__must_check\nint reviewed(int);\n")
    assert verify._same_file_wur(source, "reviewed") is True
    assert verify._same_file_wur(source, "absent") is False


def test_same_file_wur_absent_native_callee_does_not_walk_rows():
    def unexpected(source):
        pytest.fail("walked rows although the native callee is absent")
        yield

    view = module_function_view(verify, bindings={"iter_source_lines": unexpected})
    assert view._same_file_wur("// padding\n" * 2000, "absent") is False


@pytest.mark.parametrize("provider", ["compile", "escape"])
def test_same_file_wur_custom_regex_remains_authoritative(provider):
    seen = []

    def compile(pattern):
        seen.append(pattern)
        return re.compile(r"\bother\s*\(")

    def escape(text):
        seen.append(text)
        return "other"

    matcher = SimpleNamespace(compile=compile if provider == "compile" else re.compile,
                              escape=escape if provider == "escape" else re.escape)
    view = module_function_view(verify, bindings={"re": matcher})
    source = "// padding\n" * 2000 + "__must_check\nint other(void);\n"
    assert view._same_file_wur(source, "reviewed") is True
    assert len(seen) == 1


@pytest.mark.parametrize("consumer", ["release", "wur"])
def test_source_subclasses_keep_their_own_split(consumer):
    seen = []

    class Source(str):
        def split(self, separator):
            seen.append(separator)
            return ["__must_check", "int reviewed(void);"]

    source = Source("// padding\n" * 2000)
    if consumer == "release":
        assert release_view((1, 2))._function_segment(source, "owner", "c") == (
            ["__must_check", "int reviewed(void);"], 1,
        )
    else:
        assert verify._same_file_wur(source, "reviewed") is True
    assert seen == ["\n"]


def test_same_file_wur_custom_splitter_stays_authoritative():
    seen = []

    def split(source):
        seen.append(source)
        return ["__must_check", "int reviewed(void);"]

    view = module_function_view(verify, bindings={"split_lines": split})
    source = "// padding\n" * 2000
    assert view._same_file_wur(source, "reviewed") is True
    assert seen == [source]
