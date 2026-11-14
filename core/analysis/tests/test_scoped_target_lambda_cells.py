"""Comprehension target lambdas retain cells in the comprehension's lexical scope."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _bounded_body_expression_loads,
    _child_expression_is_supported,
    _comprehension_target_scope,
    _scoped_expression_loads,
    build_taint_summaries,
)


def summaries(source):
    compile(source, "<scoped-target-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("expression", ["[0 for box[(lambda: raw)()] in ()]",
                                       "[0 for box[(lambda value=raw: 0)()] in ()]",
                                       "[0 for (lambda: raw)().member in ()]"],
                         ids=["index-body", "index-default", "base"])
def test_target_lambda_retains_enclosing_cell(expression):
    result = summaries(f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested\n")["handle"]
    assert result.summary_unknown


def test_target_lambda_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        return [0 for box[(lambda: raw)()] in ()]\n    return nested\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("expression", ["[0 for box[(lambda raw: raw)(0)] in ()]",
                                       "[0 for box[(lambda: raw)()] in () for raw in ()]"],
                         ids=["lambda-parameter", "later-target"])
def test_complete_scope_bindings_mask_target_lambda(expression):
    assert not summaries(f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested\n")["handle"].summary_unknown


def test_first_iterable_stays_outside_comprehension_bindings():
    expression = "[0 for box[(lambda: raw)()] in raw for raw in ()]"
    assert summaries(f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested\n")["handle"].summary_unknown


def test_legacy_strict_wrapper_and_statement_targets_are_unchanged():
    node = ast.parse("[0 for box[(lambda: raw)()] in ()]", mode="eval").body
    target = node.generators[0].target
    assert _comprehension_target_scope(target, require_scope_free_reads=True) is None
    assert _comprehension_target_scope(target) == (frozenset(), frozenset({"box"}))
    assert _child_expression_is_supported(node)
    assert "raw" in _scoped_expression_loads(node)
    assert _bounded_body_expression_loads(ast.parse("for box[(lambda: raw)()] in ():\n pass").body) is None


@pytest.mark.parametrize("expression", ["[0 for box[(lambda: (value := raw))()] in ()]",
                                       "[0 for box[[raw for item in ()]] in ()]",
                                       "[0 for box[await (lambda: (value := raw))()] in ()]"],
                         ids=["named-write", "nested-comprehension", "awaited-write"])
def test_excluded_target_descendants_invalidate_scoped_scan(expression):
    # AST admission controls; no compiled-source claim for these expressions.
    node = ast.parse(expression, mode="eval").body
    assert not _child_expression_is_supported(node)
    assert _scoped_expression_loads(node) == frozenset()
