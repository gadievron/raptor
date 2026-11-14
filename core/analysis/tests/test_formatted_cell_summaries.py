"""Formatted expressions can retain adjacent local functions' enclosing cells."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _scope_free_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<formatted-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("definition", ["def", "async def"])
@pytest.mark.parametrize(
    "expression", ['f"{raw}"', 'f"{raw!r}"', 'f"{0:{raw}}"'],
    ids=["value", "conversion", "format-spec"],
)
def test_formatted_cell_helper_keeps_caller_raw_flow(definition, expression):
    result = summaries(
        f"import html\ndef helper(raw):\n    {definition} nested():\n        return {expression}\n"
        "    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


def test_literal_formatted_expression_has_no_enclosing_cell_read():
    result = summaries(
        'def handle(raw):\n    def nested():\n        return f"constant"\n    return nested()\n'
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_nested_default_parameter_shadow_keeps_existing_admission():
    result = summaries(
        'def handle(raw):\n    def nested(raw=0):\n        return f"{raw}"\n    return nested()\n'
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_formatted_expression_does_not_admit_nested_lambda_scope():
    expression = ast.parse('f"{(lambda raw: raw)(0)}"', mode="eval").body
    assert not _scope_free_expression_loads(expression)


def test_keyword_expansion_keeps_earlier_refusal_reason():
    result = summaries(
        'def handle(raw):\n    def nested(**unused):\n        return f"{raw}"\n'
        '    return nested(**{})\n'
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
