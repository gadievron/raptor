"""Nested comprehension scopes admit unpacking only with complete binding targets."""

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
    compile(source, "<scoped-unpacking-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize(
    "target", ["first,second", "[first,second]", "first,*rest", "(first,(second,third))"],
    ids=["tuple", "list", "starred", "nested"],
)
def test_nested_unpacking_cell_helper_keeps_caller_raw_flow(target):
    result = summaries(
        f"import html\ndef helper(raw):\n    def nested():\n"
        f"        return lambda: [raw for {target} in ()]\n"
        "    return nested()\ndef handle(raw):\n"
        "    return html.escape(raw) + helper(raw).__closure__[0].cell_contents\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize(
    "expression", ["lambda: [raw for raw,other in ()]", "lambda: [raw for first,*raw in ()]",
                   "lambda: [raw for item in () for raw,other in ()]",
                   "lambda: [0 for item in () if raw for raw,other in ()]"],
    ids=["tuple-shadow", "star-shadow", "later-body-shadow", "later-filter-shadow"],
)
def test_complete_unpacking_bindings_shadow_outer_cell(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


@pytest.mark.parametrize("target", ["obj.member", "obj[0]", "(first,obj.member)"])
def test_binding_only_mode_rejects_indirect_store_descendants(target):
    node = ast.parse(f"[0 for {target} in ()]", mode="eval").body.generators[0].target
    assert _comprehension_target_scope(node, allow_indirect_stores=False) is None
    assert _comprehension_target_scope(node) is not None


def test_nested_mixed_store_target_stays_outside_new_scoped_scan():
    expression = ast.parse("lambda: [raw for (first,obj.member) in ()]", mode="eval").body
    assert not _scoped_expression_loads(expression)


def test_first_iterable_is_not_shadowed_by_unpacking_target():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return lambda: [0 for raw,other in raw]\n"
        "    return nested()\n"
    )["handle"]
    assert result.summary_unknown
