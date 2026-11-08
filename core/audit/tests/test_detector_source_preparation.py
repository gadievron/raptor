"""Deferred source rows preserve excerpts, receipts and provider order."""

import ast
import builtins
import sys
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from core.audit import fail_open_verify as fv, return_domain as rd
from core.source.lines import SourceLineSnapshot, split_lines
from core.testing import requires_ts
from core.testing.module_views import module_function_view


@contextmanager
def whole_splits(function, source):
    if sys.getprofile() is not None:
        pytest.skip("profiling hook already owned")
    seen = []
    preparation_sites = {
        function.__code__, SourceLineSnapshot.__init__.__code__, SourceLineSnapshot.get.__code__,
    }

    def observe(frame, event, arg):
        if (event == "call" and frame.f_code is split_lines.__code__
                and frame.f_locals.get("text") is source and frame.f_back is not None
                and frame.f_back.f_code in preparation_sites):
            seen.append(source)

    try:
        sys.setprofile(observe)
        yield seen
    finally:
        sys.setprofile(None)


@pytest.mark.parametrize("newline", [pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf")])
@pytest.mark.parametrize("name", ["owner", "other", "module.owner", "absent"])
def test_python_excerpts_keep_decorators_and_source_coordinates(newline, name):
    source = ("# padding\v\u2028\n" * 2000 + "@decorate\n@other_decorator(1)\n"
              "async def owner():\n    return 1\n\ndef other():\n    pass\n").replace("\n", newline)
    rows = split_lines(source)
    expected = "\n".join(rows[2000:2004]) if name.endswith("owner") else (
        "\n".join(rows[2005:2007]) if name == "other" else ""
    )
    with whole_splits(fv._python_function_segment, source) as seen:
        assert fv._python_function_segment(source, name) == expected
    assert seen == []


def python_view(*, bindings=None, walk=None):
    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "ast" and not level:
            return SimpleNamespace(parse=ast.parse, walk=walk or ast.walk,
                                   FunctionDef=ast.FunctionDef, AsyncFunctionDef=ast.AsyncFunctionDef)
        return builtins.__import__(name, globals, locals, fromlist, level)

    return module_function_view(fv, bindings=bindings, import_hook=import_local)


def test_python_custom_splitter_stays_before_ast_walk():
    seen = []

    def split(source):
        seen.append("split")
        return ["adapter head", "adapter body"]

    def walk(tree):
        seen.append("walk")
        yield from ast.walk(tree)

    view = python_view(bindings={"split_lines": split}, walk=walk)
    assert view._python_function_segment("def owner():\n pass\n", "owner") == "adapter head\nadapter body"
    assert seen == ["split", "walk"]


def test_python_ast_callback_cannot_replace_the_eager_snapshot():
    source = "# padding\n" * 2000 + "def owner():\n    return 1\n"
    unwanted = []

    def split(source):
        unwanted.append(source)
        return ["wrong"]

    def walk(tree):
        vars(view)["split_lines"] = split
        yield from ast.walk(tree)

    view = python_view(walk=walk)
    assert view._python_function_segment(source, "owner") == "def owner():\n    return 1"
    assert unwanted == []


def test_python_nonpositive_ast_coordinates_keep_native_slice_behavior():
    source = "# padding\n" * 2000 + "def owner():\n    pass\n"

    def walk(tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                node.lineno, node.end_lineno = 0, 2002
            yield node

    view = python_view(walk=walk)
    assert view._python_function_segment(source, "owner") == "\n".join(split_lines(source)[-1:2002])


def test_python_source_adapter_keeps_its_split():
    calls = []

    class Source(str):
        def split(self, separator):
            calls.append(separator)
            return ["# padding"] * 2000 + ["adapter head", "adapter body"]

    source = Source("# padding\n" * 2000 + "def owner():\n    pass\n")
    assert fv._python_function_segment(source, "owner") == "adapter head\nadapter body"
    assert calls == ["\n"]


@requires_ts("c")
@pytest.mark.parametrize("body,count", [
    pytest.param("return target();", 0, id="no-comparison"),
    pytest.param("if (target() == -1) return -1;", 1, id="one-site"),
    pytest.param("if (target() == -1) return -1; if (other() != -1) return 0;", 2, id="two-sites"),
])
@pytest.mark.parametrize("newline", [pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf")])
def test_return_sites_prepare_exactly_one_snapshot_if_needed(body, count, newline):
    source = ("// padding\v\u2028\n" * 2000 + "int owner(void) {\n    " + body + "\n}\n").replace("\n", newline)
    with whole_splits(rd.sentinel_comparison_sites, source) as seen:
        sites = rd.sentinel_comparison_sites(source, "owner.c")
    assert len(sites) == count
    assert len(seen) == (1 if count else 0)
    assert all(site.line == 2002 and site.code == body for site in sites)


@requires_ts("c")
def test_return_walk_callback_keeps_captured_native_splitter():
    source = "// padding\n" * 2000 + "int owner(void) { if (target() == -1) return -1; }\n"
    unwanted = []
    original = rd._walk

    def split(text):
        unwanted.append(text)
        return ["wrong"]

    def walk(node):
        vars(view)["split_lines"] = split
        yield from original(node)

    view = module_function_view(rd, bindings={"_walk": walk})
    sites = view.sentinel_comparison_sites(source, "owner.c")
    assert len(sites) == 1
    assert sites[0].code == "int owner(void) { if (target() == -1) return -1; }"
    assert unwanted == []


@requires_ts("c")
def test_return_custom_splitter_stays_eager_and_bad_results_are_not_retried():
    seen = []
    source = "int owner(void) { if (target() == -1) return -1; }\n"
    original = rd._walk

    def split(text):
        seen.append("split")
        return None

    def walk(node):
        seen.append("walk")
        yield from original(node)

    view = module_function_view(rd, bindings={"split_lines": split, "_walk": walk})
    with pytest.raises(TypeError):
        view.sentinel_comparison_sites(source, "owner.c")
    assert seen.count("split") == 1
    assert seen[:2] == ["split", "walk"]
