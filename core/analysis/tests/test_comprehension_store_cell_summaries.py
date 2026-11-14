"""Store-target bases and indices can retain enclosing cells in comprehensions."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _comprehension_target_scope, build_taint_summaries


def summaries(source):
    compile(source, "<comprehension-store-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize(
    "target", ["raw.member", "raw[0]", "target[raw]", "(item, raw.member)"],
    ids=["attribute", "subscript-base", "subscript-index", "mixed-target"],
)
def test_store_target_cell_keeps_caller_raw_flow(target):
    result = summaries(
        f"import html\ndef helper(raw):\n    def nested():\n        return [0 for {target} in ()]\n"
        "    return nested\ndef handle(raw):\n"
        "    return html.escape(raw) + helper(raw).__closure__[0].cell_contents\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize(
    "expression",
    ["[0 for (raw, raw.member) in ()]", "[0 for raw.member in () for raw in ()]",
     "[0 for (raw, other[raw]) in ()]"],
    ids=["sibling-shadow", "later-shadow", "index-shadow"],
)
def test_complete_target_bindings_shadow_store_reads(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_store_target_does_not_hide_body_capture():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return [raw for obj.member in ()]\n"
        "    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_parameter_shadow_keeps_existing_admission():
    result = summaries(
        "def handle(raw):\n    def nested(raw=0):\n        return [0 for raw.member in ()]\n"
        "    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_unsupported_target_structure_has_no_scope_contract():
    assert _comprehension_target_scope(ast.Pass()) is None
