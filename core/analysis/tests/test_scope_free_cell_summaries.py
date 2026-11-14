"""Bounded expression reads retain adjacent local functions' enclosing cells."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _scope_free_expression_loads,
    build_taint_summaries,
)


def summaries(source):
    compile(source, "<scope-free-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize(
    "expression",
    ["raw.value[0]", "raw[0].value", "(0,)[raw]", "+raw", "raw + 0", "(raw,)",
     "[raw]", "{raw}", "{0: raw}", "raw if flag else 0", "raw and 0", "raw == 0",
     "f(raw)", "f(value=raw)", "f(*raw)"],
    ids=["member-index", "index-member", "slice", "unary", "binary", "tuple",
         "list", "set", "dict", "conditional", "boolean", "comparison",
         "call", "keyword", "starred"],
)
def test_scope_free_cell_helper_keeps_caller_raw_flow(expression):
    result = summaries(
        f"import html\ndef helper(raw, flag):\n    def nested():\n        return {expression}\n"
        "    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw, True)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


def test_existing_indexed_base_refusal_survives_unsupported_slice():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return raw[(lambda: 0)()]\n"
        "    return nested()\n"
    )["handle"]
    assert result.summary_unknown


@pytest.mark.parametrize("signature", ["raw", "raw=(0,)"])
def test_parameter_shadow_does_not_become_a_cell(signature):
    result = summaries(
        f"def handle(raw):\n    def nested({signature}):\n        return (raw,)\n"
        "    return nested(0)\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


@pytest.mark.parametrize("expression", ["lambda raw: raw", "[raw for raw in seq]", "(raw := 0)"])
def test_nested_scope_and_binding_shapes_are_not_scanned(expression):
    assert not _scope_free_expression_loads(ast.parse(expression, mode="eval").body)


def test_unused_scope_free_cell_keeps_existing_admission():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return (raw,)\n    return 0\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)
