"""Bounded nested expression scopes retain cells without crossing parameter shadows."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _scoped_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<scoped-expression-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize(
    "expression", ["lambda: (lambda: raw)", "lambda: [raw for item in (0,)]",
                   "lambda: {0:raw for item in (0,)}", "[lambda: raw for item in (0,)]"],
    ids=["nested-lambda", "lambda-list", "lambda-dict", "list-lambda"],
)
def test_deeper_scope_capture_refuses_known_summary(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested()\n"
    )["handle"]
    assert result.summary_unknown


def test_deeper_lambda_helper_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        return lambda: (lambda: raw)\n"
        "    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)()()\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize(
    "expression", ["lambda raw: (lambda: raw)", "lambda: [raw for raw in ()]",
                   "[lambda: raw for raw in ()]", "[lambda value=raw: value for raw in ()]",
                   "[0 for item in () if raw for raw in ()]"],
    ids=["lambda-shadow", "target-shadow", "target-cell", "target-default", "late-target"],
)
def test_complete_scope_bindings_hide_outer_names(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_nested_default_reads_surrounding_scope_before_shadow():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return lambda: (lambda raw=raw: raw)\n"
        "    return nested()\n"
    )["handle"]
    assert result.summary_unknown


def test_unsupported_binder_does_not_become_a_certified_read_scan():
    expression = ast.parse("lambda: (raw, (raw := 0))", mode="eval").body
    assert not _scoped_expression_loads(expression)


def test_target_expressions_remain_outside_new_scoped_scan():
    expression = ast.parse("lambda: [raw for target[0] in ()]", mode="eval").body
    assert not _scoped_expression_loads(expression)


def test_existing_direct_base_refusal_survives_unsupported_scoped_part():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return raw[(lambda: (value := 0))()]\n"
        "    return nested()\n"
    )["handle"]
    assert result.summary_unknown
