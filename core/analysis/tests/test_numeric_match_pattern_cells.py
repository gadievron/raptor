"""Signed and complex literals expose cells without numeric evaluation."""

import ast
from textwrap import indent

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _bounded_body_expression_loads,
    _match_literal_expression,
    build_taint_summaries,
)


def summaries(source):
    compile(source, "<numeric-match-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def source_for(pattern, child=False, header=""):
    body = f"match 0:\n case {pattern}:\n  return raw\n"
    if child:
        body = f"def child({header}):\n" + indent(body, " ") + "return child\n"
        header = ""
    return f"def handle(raw):\n    def nested({header}):\n" + indent(body, "        ") + "    return nested\n"


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("mapping", [False, True], ids=["value", "key"])
@pytest.mark.parametrize("literal", ["-1", "-1.5", "-1j", "1+2j", "1-2j", "-1+2j"],
                         ids=["integer", "float", "imaginary", "complex-add", "complex-sub", "negative-real"])
def test_numeric_pattern_retains_body_cell(literal, mapping, child):
    pattern = "{" + literal + ": _}" if mapping else literal
    assert summaries(source_for(pattern, child))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("mapping", [False, True], ids=["value", "key"])
def test_numeric_pattern_keeps_caller_raw_flow(mapping, child):
    pattern = "{-1+2j: _}" if mapping else "-1+2j"
    source = source_for(pattern, child).replace("def handle(raw):", "def helper(raw):").replace("    return nested\n", "    return nested()\n")
    source = "import html\n" + source + "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    result = summaries(source)
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("expression", ["-raw", "raw+2j", "1+raw", "1*2j", "invoke()", "raw[0]", "-True", "-(1+2j)"],
                         ids=["negative-name", "left-name", "right-name", "multiply", "call", "subscript", "bool", "nested-arithmetic"])
def test_literal_validator_does_not_admit_general_expressions(expression):
    # Expression-AST controls, not compiled source-pattern witnesses.
    assert not _match_literal_expression(ast.parse(expression, mode="eval").body)


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_numeric_pattern_parameter_masks_outer_cell(child):
    assert not summaries(source_for("-1", child, "raw"))["handle"].summary_unknown


def test_later_capture_invalidates_complete_numeric_scan():
    body = "match raw:\n case -1:\n  raw\n case (1+2j) as value:\n  return value"
    assert _bounded_body_expression_loads(ast.parse(body).body) is None
