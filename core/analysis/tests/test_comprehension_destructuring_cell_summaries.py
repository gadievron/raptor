"""Comprehension unpacking binds names without hiding unrelated captured cells."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _comprehension_target_bindings,
    build_taint_summaries,
)


def summaries(source):
    compile(source, "<comprehension-destructuring-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize(
    "target", ["first, second", "[first, second]", "first, *rest", "(first, (second, third))"],
    ids=["tuple", "list", "starred", "nested"],
)
def test_destructuring_helper_keeps_captured_cell_flow(target):
    result = summaries(
        f"import html\ndef helper(raw):\n    def nested():\n        return [raw for {target} in ()]\n"
        "    return nested\ndef handle(raw):\n"
        "    return html.escape(raw) + helper(raw).__closure__[0].cell_contents\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize(
    "expression",
    ["[raw for raw, second in ()]", "[raw for first, *raw in ()]",
     "[raw for item in () for raw, second in ()]",
     "[0 for item in () if raw for raw, second in ()]"],
    ids=["tuple-shadow", "star-shadow", "late-body-shadow", "late-filter-shadow"],
)
def test_complete_destructuring_target_set_shadows_outer_names(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


@pytest.mark.parametrize("target", ["obj.member", "obj[0]", "(item, obj.member)"])
def test_store_expressions_are_not_lexical_binding_targets(target):
    node = ast.parse(f"[0 for {target} in ()]", mode="eval").body
    assert _comprehension_target_bindings(node.generators[0].target) is None


def test_unsupported_store_keeps_first_iterable_refusal():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return [0 for obj.member in raw]\n"
        "    return nested()\n"
    )["handle"]
    assert result.summary_unknown


def test_default_parameter_shadow_keeps_existing_admission():
    result = summaries(
        "def handle(raw):\n    def nested(raw=0):\n        return [raw for first, second in ()]\n"
        "    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)
