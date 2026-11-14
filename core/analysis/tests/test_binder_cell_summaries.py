"""Assignment-expression ownership distinguishes captured cells from lambda locals."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _lambda_body_bindings,
    _scoped_expression_loads,
    _scope_free_expression_loads,
    build_taint_summaries,
)


def summaries(source):
    compile(source, "<binder-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize(
    "expression", ["lambda: (value := raw)", "lambda: [(value := raw) for item in (0,)]",
                   "lambda: (lambda value=(temp := raw): value)"],
    ids=["lambda-body", "comprehension-rhs", "nested-default-rhs"],
)
def test_lambda_assignment_rhs_keeps_caller_raw_flow(expression):
    result = summaries(
        f"import html\ndef helper(raw):\n    def nested():\n        return {expression}\n"
        "    return nested()\ndef handle(raw):\n"
        "    return html.escape(raw) + helper(raw).__closure__[0].cell_contents\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


def test_root_assignment_rhs_reads_enclosing_cell():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return (value := raw)\n    return nested()\n"
    )["handle"]
    assert result.summary_unknown


@pytest.mark.parametrize(
    "expression", ["lambda: (raw := 0)", "lambda: (raw, (raw := 0))",
                   "lambda: (lambda: (raw := 0))", "lambda: (lambda value=(raw := 0): value)",
                   "lambda value=(raw := 0): value", "lambda: [(raw := item) for item in ()]"],
    ids=["body-shadow", "earlier-read", "nested-body", "nested-default", "root-default", "comp-binding"],
)
def test_assignment_owner_shadows_outer_cell(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_nested_body_binding_does_not_shadow_outer_lambda_read():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return lambda: (raw, (lambda: (raw := 0)))\n"
        "    return nested()\n"
    )["handle"]
    assert result.summary_unknown


def test_scope_free_grammar_still_excludes_assignment_expression():
    expression = ast.parse("(value := raw)", mode="eval").body
    assert not _scope_free_expression_loads(expression)
    assert _scoped_expression_loads(expression) == frozenset({"raw"})


def test_malformed_assignment_target_aborts_binding_and_read_scans():
    expression = ast.NamedExpr(target=ast.Attribute(value=ast.Name(id="obj"), attr="member"),
                               value=ast.Name(id="raw", ctx=ast.Load()))
    assert _lambda_body_bindings(expression) is None
    assert not _scoped_expression_loads(expression)
