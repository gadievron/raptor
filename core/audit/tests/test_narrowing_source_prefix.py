"""Go auto-detection examines only its existing thirty source rows."""

import builtins
from types import SimpleNamespace

import pytest

from core.audit import condition_smt as smt
from core.testing.module_views import module_function_view


class CSelected(Exception):
    pass


def probe_view(probe, *, splitter=None, header=None, rows=None):
    views = []

    def sanitized(source, **kwargs):
        views.append(kwargs["language"])
        return probe if len(views) == 1 else "analysis body\n"

    def c_context(*args, **kwargs):
        raise CSelected

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "source_view" and level == 1:
            return SimpleNamespace(sanitized_view=sanitized)
        if name == "narrowing_guards" and level == 1:
            return SimpleNamespace(NarrowingGuardContext=c_context, integer_range=None)
        if name == "core.source.lines" and not level and splitter is not None:
            return SimpleNamespace(split_lines=splitter)
        return builtins.__import__(name, globals, locals, fromlist, level)

    bindings = {"_check_integer_narrowing_go": lambda lines: smt.IntegerNarrowingResult(reasoning="go selected")}
    if header is not None:
        bindings["_SMT_GO_DECL_RE"] = header
    if rows is not None:
        bindings["iter_source_lines"] = rows
    return module_function_view(smt, bindings=bindings, import_hook=import_local)


@pytest.mark.parametrize("position", [1, 30, 31, None], ids=["first", "thirtieth", "too-late", "absent"])
@pytest.mark.parametrize("newline", [pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf")])
def test_detection_keeps_thirty_row_boundary(position, newline):
    lines = ["// filler\v\f\u2028"] * 2000
    if position is not None:
        lines[position - 1] = "package owned"
    source = newline.join(lines)
    seen = []
    original = smt.iter_source_lines

    def rows(text):
        for line in original(text):
            seen.append(line)
            yield line

    view = probe_view(source, rows=rows)
    if position is not None and position <= 30:
        assert view.check_integer_narrowing("owned").reasoning == "go selected"
        assert len(seen) == position
    else:
        with pytest.raises(CSelected):
            view.check_integer_narrowing("owned")
        assert len(seen) == 30


def test_custom_splitter_keeps_slice_before_pattern_callbacks():
    seen = []

    class Rows(list):
        def __getitem__(self, key):
            seen.append(("slice", key))
            return super().__getitem__(key)

    def split(source):
        seen.append(("split", source))
        return Rows(["package owned"] + ["// filler"] * 40)

    class Header:
        def match(self, line):
            seen.append(("match", line))
            return smt._SMT_GO_DECL_RE.match(line)

    source = "// padding\n" * 2000
    view = probe_view(source, splitter=split, header=Header())
    assert view.check_integer_narrowing("owned").reasoning == "go selected"
    assert seen[:3] == [("split", source), ("slice", slice(None, 30)), ("match", "package owned")]


def test_source_adapter_keeps_its_split():
    seen = []

    class Source(str):
        def split(self, separator):
            seen.append(separator)
            return ["package adapter"]

    view = probe_view(Source("ignored"))
    assert view.check_integer_narrowing("owned").reasoning == "go selected"
    assert seen == ["\n"]
