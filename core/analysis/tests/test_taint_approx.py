"""Tests for core.analysis.taint_approx.

The tree-walk tests use fake nodes and are hermetic (no tree-sitter
needed); extraction tests require the real C grammar and skip when
``tree_sitter_c`` is not installed.
"""

from __future__ import annotations

import sys

import pytest

from core.analysis.taint_approx import (
    CTaintApprox,
    _find_function_declarator,
    _find_identifier,
    _resolve_callee,
    _scan_calls,
    _scan_opaque_assignments,
    _walk_top_level,
    extract_taint_approx_c,
)


class TestExtractTaintApproxC:
    @pytest.fixture(autouse=True)
    def _require_c_grammar(self):
        pytest.importorskip("tree_sitter_c")
    def test_direct_param_to_dangerous_sink(self):
        code = """
void parse_header(char *buf, int len) {
    memcpy(dst, buf, len);
}
"""
        results = extract_taint_approx_c(code)
        assert "parse_header" in results
        approx = results["parse_header"]
        assert approx.params == ["buf", "len"]
        assert approx.has_any_dangerous()
        assert 0 in approx.dangerous_flows
        assert 1 in approx.dangerous_flows

    def test_no_dangerous_calls(self):
        code = """
int add(int a, int b) {
    return a + b;
}
"""
        results = extract_taint_approx_c(code)
        assert "add" in results
        approx = results["add"]
        assert not approx.has_any_dangerous()
        assert approx.direct_flows == {}

    def test_direct_flow_non_dangerous(self):
        code = """
void wrapper(int x) {
    helper(x);
}
"""
        results = extract_taint_approx_c(code)
        approx = results["wrapper"]
        assert 0 in approx.direct_flows
        assert approx.direct_flows[0] == [("helper", 0)]
        assert not approx.has_any_dangerous()

    def test_param_at_different_arg_positions(self):
        code = """
void copy(char *dst, const char *src, int n) {
    memcpy(dst, src, n);
}
"""
        results = extract_taint_approx_c(code)
        approx = results["copy"]
        assert 0 in approx.dangerous_flows
        assert 1 in approx.dangerous_flows
        assert 2 in approx.dangerous_flows

    def test_opaque_flow_through_pointer(self):
        code = """
void process(char *buf, int len) {
    char *p = buf;
    memcpy(dst, p, len);
}
"""
        results = extract_taint_approx_c(code)
        approx = results["process"]
        assert 1 in approx.dangerous_flows
        assert 0 not in approx.dangerous_flows

    def test_multiple_functions(self):
        code = """
void f1(int x) {
    system(x);
}

void f2(int y) {
    printf(y);
}

int f3(int z) {
    return z;
}
"""
        results = extract_taint_approx_c(code)
        assert len(results) == 3
        assert results["f1"].has_any_dangerous()
        assert results["f2"].has_any_dangerous()
        assert not results["f3"].has_any_dangerous()

    def test_no_params(self):
        code = """
void init(void) {
    setup();
}
"""
        results = extract_taint_approx_c(code)
        assert "init" in results
        assert results["init"].params == []
        assert not results["init"].has_any_dangerous()

    def test_nested_calls(self):
        code = """
void handler(char *cmd) {
    log(strlen(cmd));
    system(cmd);
}
"""
        results = extract_taint_approx_c(code)
        approx = results["handler"]
        assert approx.has_dangerous_param(0)
        dangerous_callees = [c for c, _ in approx.dangerous_flows[0]]
        assert "system" in dangerous_callees

    def test_pointer_return_function(self):
        code = """
char *get_name(const char *input, int len) {
    memcpy(buf, input, len);
    return buf;
}
"""
        results = extract_taint_approx_c(code)
        assert "get_name" in results
        approx = results["get_name"]
        assert approx.has_any_dangerous()

    def test_empty_source(self):
        results = extract_taint_approx_c("")
        assert results == {}

    def test_non_identifier_argument_not_matched(self):
        code = """
void f(int x) {
    memcpy(dst, &x, sizeof(x));
}
"""
        results = extract_taint_approx_c(code)
        approx = results["f"]
        assert 0 not in approx.dangerous_flows or len(approx.dangerous_flows.get(0, [])) == 0

    def test_field_access_callee(self):
        code = """
void handler(char *data) {
    obj.process(data);
}
"""
        results = extract_taint_approx_c(code)
        approx = results["handler"]
        assert 0 in approx.direct_flows
        callee_names = [c for c, _ in approx.direct_flows[0]]
        assert "obj.process" in callee_names


DEEP = sys.getrecursionlimit() * 3


class _FakeNode:
    """Minimal stand-in for a tree-sitter node."""

    def __init__(self, type_: str, children=None, text=b"", is_named=True):
        self.type = type_
        self.children = children or []
        self.text = text
        self.is_named = is_named


def _deep_chain(depth: int, inner: _FakeNode, wrapper: str) -> _FakeNode:
    node = inner
    for _ in range(depth):
        node = _FakeNode(wrapper, [node])
    return node


class TestIterativeWalks:
    """The tree walks are iterative: a target file with deep nesting
    must not abort the prep pass with RecursionError."""

    def test_walk_top_level_survives_deep_nesting(self):
        root = _deep_chain(DEEP, _FakeNode("identifier"), "compound_statement")
        results: dict[str, CTaintApprox] = {}
        _walk_top_level(root, results)          # must not raise
        assert results == {}

    def test_scan_calls_survives_deep_nesting(self):
        root = _deep_chain(DEEP, _FakeNode("identifier"), "binary_expression")
        approx = CTaintApprox(function="f", params=["p"])
        _scan_calls(root, {"p"}, {"p": 0}, approx)   # must not raise
        assert approx.direct_flows == {}

    def test_scan_opaque_assignments_survives_deep_nesting(self):
        root = _deep_chain(DEEP, _FakeNode("identifier"), "binary_expression")
        approx = CTaintApprox(function="f", params=["p"])
        _scan_opaque_assignments(root, {"p"}, approx)  # must not raise
        assert not approx.has_opaque_flow

    def test_find_identifier_survives_deep_nesting(self):
        leaf = _FakeNode("identifier", text=b"needle")
        root = _deep_chain(DEEP, leaf, "pointer_declarator")
        assert _find_identifier(root) == "needle"

    def test_find_function_declarator_survives_deep_nesting(self):
        leaf = _FakeNode("function_declarator")
        root = _deep_chain(DEEP, leaf, "pointer_declarator")
        assert _find_function_declarator(root) is leaf

    def test_resolve_callee_unwraps_deep_parens(self):
        leaf = _FakeNode("identifier", text=b"fnptr")
        root = _deep_chain(DEEP, leaf, "parenthesized_expression")
        assert _resolve_callee(root) == ["fnptr"]

    def test_walk_top_level_still_finds_functions(self):
        # Pre-order behaviour pin: functions nested under translation
        # unit children are analysed; the walk does not descend into a
        # function_definition body.
        decl = _FakeNode("function_declarator", [
            _FakeNode("identifier", text=b"outer"),
            _FakeNode("parameter_list"),
        ])
        fn = _FakeNode("function_definition", [decl])
        root = _FakeNode("translation_unit", [fn])
        results: dict[str, CTaintApprox] = {}
        _walk_top_level(root, results)
        assert list(results) == ["outer"]


class TestEndToEndDeepFile:
    def test_deeply_nested_c_file_does_not_abort(self):
        pytest.importorskip("tree_sitter_c")
        depth = 2000
        body = "{\n" * depth + "}\n" * depth
        code = (
            "void deep(char *buf) " + body +
            "\nvoid after(char *src, int n) { memcpy(dst, src, n); }\n"
        )
        results = extract_taint_approx_c(code)   # must not raise
        # The later, well-formed function is still analysed.
        assert "after" in results
        assert results["after"].has_any_dangerous()

    def test_normal_extraction_unchanged(self):
        pytest.importorskip("tree_sitter_c")
        code = (
            "void parse(char *buf, int len) {\n"
            "    memcpy(dst, buf, len);\n"
            "}\n"
        )
        results = extract_taint_approx_c(code)
        assert results["parse"].params == ["buf", "len"]
        assert 0 in results["parse"].dangerous_flows


class TestCTaintApprox:
    def test_to_dict(self):
        approx = CTaintApprox(
            function="f",
            params=["x", "y"],
            direct_flows={0: [("g", 0)]},
            dangerous_flows={0: [("system", 0)]},
            has_opaque_flow=True,
        )
        d = approx.to_dict()
        assert d["function"] == "f"
        assert d["params"] == ["x", "y"]
        assert d["has_opaque_flow"] is True
        assert "0" in d["direct_flows"]
        assert "0" in d["dangerous_flows"]

    def test_has_dangerous_param(self):
        approx = CTaintApprox(
            function="f", params=["x"],
            dangerous_flows={0: [("system", 0)]},
        )
        assert approx.has_dangerous_param(0)
        assert not approx.has_dangerous_param(1)

    def test_has_any_dangerous_empty(self):
        approx = CTaintApprox(function="f", params=["x"])
        assert not approx.has_any_dangerous()
