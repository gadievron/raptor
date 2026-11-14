"""Awaited target indices expose lexical cells without executing comprehensions."""

import ast
from textwrap import indent

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<awaited-target-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def source_for(expression, deep=False, header=""):
    if deep:
        body = f"async def child({header}):\n return {expression}\nreturn child\n"
        definition = "def nested():"
    else:
        body = f"return {expression}\n"
        definition = f"async def nested({header}):"
    return f"def handle(raw):\n    {definition}\n" + indent(body, "        ") + "    return nested\n"


@pytest.mark.parametrize("deep", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("expression", ["[0 for box[await raw] in ()]", "[0 for box[await raw.member] in ()]",
                                       "[0 for box[await wrapper(raw)] in ()]",
                                       "[0 for box[(lambda value=await raw: 0)()] in ()]"],
                         ids=["index", "attribute", "call", "lambda-default"])
def test_awaited_target_retains_cell(expression, deep):
    assert summaries(source_for(expression, deep))["handle"].summary_unknown


@pytest.mark.parametrize("deep", [False, True], ids=["root", "child"])
def test_awaited_target_keeps_caller_raw_flow(deep):
    source = source_for("[0 for box[await raw] in ()]", deep).replace("def handle(raw):", "def helper(raw):")
    if deep:
        source = source.replace("    return nested\n", "    return nested()\n")
    source = "import html\n" + source + "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    result = summaries(source)
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("deep", [False, True], ids=["root", "child"])
def test_later_target_masks_await_operand(deep):
    expression = "[0 for box[await raw] in () for raw in ()]"
    assert not summaries(source_for(expression, deep))["handle"].summary_unknown


@pytest.mark.parametrize("deep", [False, True], ids=["root", "child"])
def test_function_parameter_masks_await_operand(deep):
    assert not summaries(source_for("[0 for box[await raw] in ()]", deep, "raw"))["handle"].summary_unknown


def test_first_iterable_remains_outside_target_bindings():
    expression = "[0 for box[await raw] in raw for raw in ()]"
    assert summaries(source_for(expression))["handle"].summary_unknown


def test_ordinary_statement_await_target_remains_strictly_excluded():
    body = "async def child():\n for box[await raw] in ():\n  pass"
    compile("def outer(raw):\n " + body.replace("\n", "\n "), "<ordinary-await-target>", "exec", dont_inherit=True)
    assert _bounded_body_expression_loads(ast.parse(body).body) is None
