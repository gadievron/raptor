"""Nested store-target reads require an explicit complete expression grammar."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _comprehension_target_scope,
    _scoped_expression_loads,
    build_taint_summaries,
)


def summaries(source):
    compile(source, "<scoped-indirect-target-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize(
    "target", ["raw.member", "raw[0]", "target[raw]", "(item,raw.member)"],
    ids=["attribute", "subscript-base", "subscript-index", "mixed"],
)
def test_nested_store_cell_helper_keeps_caller_raw_flow(target):
    result = summaries(
        f"import html\ndef helper(raw):\n    def nested():\n"
        f"        return lambda: [0 for {target} in ()]\n"
        "    return nested()\ndef handle(raw):\n"
        "    return html.escape(raw) + helper(raw).__closure__[0].cell_contents\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize(
    "expression", ["lambda: [0 for (raw,raw.member) in ()]",
                   "lambda: [0 for raw.member in () for raw in ()]",
                   "lambda raw: [0 for raw.member in ()]"],
    ids=["sibling-shadow", "later-shadow", "lambda-shadow"],
)
def test_complete_bindings_shadow_target_expression_reads(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_strict_mode_rejects_unsupported_index_but_default_keeps_known_base():
    node = ast.parse("[0 for raw[(lambda: 0)()] in ()]", mode="eval").body.generators[0].target
    assert _comprehension_target_scope(node, require_scope_free_reads=True) is None
    assert _comprehension_target_scope(node) == (frozenset(), frozenset({"raw"}))


def test_binding_only_mode_still_rejects_supported_store_expression():
    node = ast.parse("[0 for raw.member in ()]", mode="eval").body.generators[0].target
    assert _comprehension_target_scope(node, allow_indirect_stores=False) is None


def test_unsupported_index_still_aborts_new_scoped_scan():
    expression = ast.parse("lambda: [raw for target[[0 for item in ()]] in ()]", mode="eval").body
    assert not _scoped_expression_loads(expression)


def test_existing_direct_base_refusal_survives_strict_target_rejection():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return raw[(lambda: [0 for obj.member in ()])()]\n"
        "    return nested()\n"
    )["handle"]
    assert result.summary_unknown
