"""Yield operands retain lexical cells without generator iteration or result proof."""

import ast
from textwrap import indent

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _child_expression_is_supported,
    _scoped_expression_loads,
    build_taint_summaries,
)


def summaries(source):
    compile(source, "<yield-expression-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def source_for(expression, child=False, header=""):
    if child:
        body = f"def child({header}):\n return ({expression})\nreturn child\n"
        definition = "def nested():"
    else:
        body = f"return ({expression})\n"
        definition = f"def nested({header}):"
    return f"def handle(raw):\n    {definition}\n" + indent(body, "        ") + "    return nested\n"


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("expression", ["yield raw", "yield from raw", "yield raw.member", "yield from raw.member",
                                       "yield wrapper(raw)", "raw, (yield)", "lambda: (yield raw)",
                                       "lambda value=raw: (yield 0)"],
                         ids=["yield", "yield-from", "attribute", "delegated-attribute", "call", "bare-yield-sibling", "generator-lambda", "lambda-default"])
def test_yield_expression_retains_enclosing_cell(expression, child):
    assert summaries(source_for(expression, child))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_yield_expression_keeps_caller_raw_flow(child):
    source = source_for("yield raw", child).replace("def handle(raw):", "def helper(raw):")
    if child:
        source = source.replace("    return nested\n", "    return nested()\n")
    source = "import html\n" + source + "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    result = summaries(source)
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("expression", ["yield", "yield 0", "yield from ()", "lambda raw: (yield raw)", "lambda: (yield (raw := 0))"],
                         ids=["bare", "constant", "constant-delegation", "lambda-parameter", "lambda-own-binding"])
def test_yield_scope_controls_do_not_capture_outer_cell(expression, child):
    assert not summaries(source_for(expression, child))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_yield_parameter_masks_outer_cell(child):
    assert not summaries(source_for("yield raw", child, "raw"))["handle"].summary_unknown


def test_unsupported_yielded_descendant_invalidates_complete_scan():
    expression = "(yield [raw for box[[raw for item in ()]] in ()])"
    compile(source_for(expression), "<yield-target-control>", "exec", dont_inherit=True)
    node = ast.parse(expression, mode="eval").body
    assert not _child_expression_is_supported(node)
    assert _scoped_expression_loads(node) == frozenset()


@pytest.mark.parametrize("body", ["yield raw", "yield from raw"], ids=["yield", "yield-from"])
def test_own_generator_result_refusal_keeps_prior_reason(body):
    result = summaries("def stream(raw):\n    " + body + "\n")["stream"]
    assert result.summary_unknown_reason == "generator iteration outputs are not modelled"
