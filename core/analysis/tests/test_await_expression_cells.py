"""Await operands expose lexical cells without coroutine execution or result proof."""

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
    compile(source, "<await-expression-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def source_for(expression, child=False, header=""):
    if child:
        body = f"async def child({header}):\n return {expression}\nreturn child\n"
        definition = "def nested():"
    else:
        body = f"return {expression}\n"
        definition = f"async def nested({header}):"
    return f"def handle(raw):\n    {definition}\n" + indent(body, "        ") + "    return nested\n"


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("expression", ["await raw", "await raw.member", "await wrapper(raw)",
                                       "(lambda value=await raw: 0)", "[await raw for item in ()]",
                                       "[item for item in await raw]", "f'{await raw}'"],
                         ids=["direct", "attribute", "call", "lambda-default", "comprehension-payload", "first-iterable", "fstring"])
def test_await_expression_retains_enclosing_cell(expression, child):
    assert summaries(source_for(expression, child))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_await_expression_keeps_caller_raw_flow(child):
    source = source_for("await raw", child).replace("def handle(raw):", "def helper(raw):")
    if child:
        source = source.replace("    return nested\n", "    return nested()\n")
    source = "import html\n" + source + "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    result = summaries(source)
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("expression", ["await 0", "await (lambda raw: raw)(0)", "[await raw for raw in ()]"],
                         ids=["constant", "lambda-parameter", "comprehension-target"])
def test_await_scope_controls_do_not_capture_outer_cell(expression, child):
    assert not summaries(source_for(expression, child))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_await_parameter_masks_outer_cell(child):
    assert not summaries(source_for("await raw", child, "raw"))["handle"].summary_unknown


def test_awaited_comprehension_target_stays_outside_strict_target_grammar():
    expression = "[0 for box[await raw] in ()]"
    compile(source_for(expression), "<await-target-control>", "exec", dont_inherit=True)
    node = ast.parse(expression, mode="eval").body
    assert not _child_expression_is_supported(node)
    assert _scoped_expression_loads(node) == frozenset()


def test_generator_refusal_keeps_prior_reason():
    result = summaries("def handle(raw):\n    yield raw\n")["handle"]
    assert result.summary_unknown_reason == "generator iteration outputs are not modelled"
