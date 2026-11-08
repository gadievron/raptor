"""Function-window preparation keeps language routing and provider order."""

import builtins
from types import SimpleNamespace

import pytest

from core.audit import fail_open_verify as fv
from core.audit.fail_open_roles import RoleContext
from core.source.lines import split_lines
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("start,end", [(1, 3), (2500, 2503), (2502, 2510), (1, 9999), (0, 3), (3, 2)])
def test_native_segments_match_eager_slices(start, end):
    source = "padding\r\n" * 2500 + "\n\r\n"
    assert fv._segment_for_span(source, (start, end)) == "\n".join(split_lines(source)[start - 1:end])


def test_coordinate_adapter_keeps_split_before_indexing():
    seen = []

    class Span:
        def __getitem__(self, index):
            seen.append(index)
            return (1, 2)[index]

    def split(source):
        seen.append("split")
        return ["first", "", "last"]

    view = module_function_view(fv, bindings={"split_lines": split})
    assert view._segment_for_span("padding\n" * 2500, Span()) == "first\n"
    assert seen == ["split", 0, 1]


@pytest.mark.parametrize("kind", ["go", "javascript", "swift", "rust", "c"])
@pytest.mark.parametrize("custom_split", [False, True], ids=["native", "adapter"])
def test_language_consumers_keep_exact_function_text(kind, custom_split):
    source = "padding\r\n" * 2500 + "\n\r\n"
    observed = []
    split_calls = []

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "fail_open_lang":
            return SimpleNamespace(_ts_parser=lambda language: object())
        return builtins.__import__(name, globals, locals, fromlist, level)

    def candidates(hypothesis, segment):
        observed.append(segment)
        return []

    def split(text):
        split_calls.append(text)
        return ["adapter", "", "tail"]

    span = (1, 2) if custom_split else (2500, 2503)
    bindings = {name: lambda *args, **kwargs: span for name in [
        "go_function_span", "js_function_span", "swift_function_span", "rust_function_span", "c_function_span",
    ]}
    bindings["_candidate_callees"] = candidates
    if custom_split:
        bindings["split_lines"] = split
    view = module_function_view(fv, bindings=bindings, import_hook=import_local)
    if kind == "go":
        observed.append(view._go_segment(source, "owner"))
    elif kind == "javascript":
        observed.append(view._js_segment(source, "owner", "javascript"))
    else:
        args = [source, "owner." + kind, "owner", "hypothesis"]
        if kind == "c":
            args.append("c")
        args.extend([RoleContext(), None])
        check = {"c": view._run_c_check, "swift": view._run_swift_erasure_check, "rust": view._run_rust_check}[kind]
        result = check(*args)
        assert result.reason.startswith(fv.REASON_HYPOTHESIS_UNBINDABLE)
    expected = "adapter\n" if custom_split else "\n".join(split_lines(source)[2499:2503])
    assert observed == [expected]
    assert split_calls == ([source] if custom_split else [])


def test_c_unresolved_span_keeps_split_before_adapter_truth():
    seen = []

    class Span:
        def __bool__(self):
            seen.append("truth")
            return False

    def split(source):
        seen.append("split")
        return []

    view = module_function_view(fv, bindings={"split_lines": split, "c_function_span": lambda *args, **kwargs: Span()})
    result = view._run_c_check("padding\n" * 2500, "owner.c", "owner", "", "c", RoleContext(), None)
    assert result.reason.startswith(fv.REASON_SPAN_UNRESOLVED)
    assert seen == ["split", "truth"]


def test_string_adapter_keeps_its_split():
    seen = []

    class Source(str):
        def split(self, separator):
            seen.append(separator)
            return ["first", "", "last"]

    assert fv._segment_for_span(Source("ignored"), (1, 2)) == "first\n"
    assert seen == ["\n"]
