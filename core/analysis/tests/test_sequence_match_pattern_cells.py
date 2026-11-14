"""Noncapturing sequence patterns expose cells without sequence-operation proof."""

import ast
from textwrap import indent

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<sequence-match-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def source_for(pattern, child=False, header=""):
    body = f"match raw:\n case {pattern}:\n  return raw\n"
    if child:
        body = f"def child({header}):\n" + indent(body, " ") + "return child\n"
        header = ""
    return f"def handle(raw):\n    def nested({header}):\n" + indent(body, "        ") + "    return nested\n"


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("pattern", ["[]", "[_]", "[*_]", "[0, None]", "[[0], *_]", "(_, True)"],
                         ids=["empty", "wildcard", "star-wildcard", "literals", "nested", "tuple"])
def test_sequence_pattern_retains_cell(pattern, child):
    assert summaries(source_for(pattern, child))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_sequence_pattern_keeps_caller_raw_flow(child):
    source = source_for("[_, *_]", child).replace("def handle(raw):", "def helper(raw):").replace("    return nested\n", "    return nested()\n")
    source = "import html\n" + source + "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    result = summaries(source)
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_sequence_pattern_parameter_masks_outer_cell(child):
    assert not summaries(source_for("[_]", child, "raw"))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("pattern", ["[value]", "[*values]", "[[value]]", "[0, raw.member]", "[0, {}]", "[0, Value()]", "[0, 1 | 2]"],
                         ids=["capture", "named-star", "nested-capture", "dotted-child", "mapping-child", "class-child", "or-child"])
def test_unsupported_sequence_child_invalidates_complete_scan(pattern, child):
    tree = ast.parse(source_for(pattern, child))
    assert _bounded_body_expression_loads(tree.body[0].body[0].body) is None


def test_later_case_capture_invalidates_complete_sequence_scan():
    body = "match raw:\n case [0]:\n  raw\n case [value]:\n  return value"
    assert _bounded_body_expression_loads(ast.parse(body).body) is None


def test_outer_capture_keeps_prior_reason():
    source = source_for("[_]").replace("    def nested():", "    match raw:\n        case value:\n            pass\n    def nested():")
    assert summaries(source)["handle"].summary_unknown_reason == "pattern capture value transfer is not modelled"
