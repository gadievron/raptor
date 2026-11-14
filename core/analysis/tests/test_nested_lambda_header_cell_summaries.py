"""Returned lambdas read defaults and bodies in different binding scopes."""

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<nested-lambda-header-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize(
    "expression", ["lambda: raw", "lambda value=raw: value", "lambda *, value=raw: value",
                   "lambda raw=raw: raw"],
    ids=["body", "default", "keyword-default", "default-before-shadow"],
)
def test_nested_lambda_cell_helper_keeps_caller_raw_flow(expression):
    result = summaries(
        f"import html\ndef helper(raw):\n    def nested():\n        return {expression}\n"
        "    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)()\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize(
    "signature", ["raw", "raw, /", "*, raw", "*raw", "**raw", "raw=0"],
    ids=["positional", "posonly", "keyword-only", "vararg", "kwarg", "default"],
)
def test_lambda_parameter_shadow_does_not_read_outer_cell(signature):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        return lambda {signature}: raw\n"
        "    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_named_function_parameter_shadow_keeps_existing_admission():
    result = summaries(
        "def handle(raw):\n    def nested(raw=0):\n        return lambda: raw\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_unused_named_function_with_lambda_keeps_existing_admission():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return lambda: raw\n    return 0\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_keyword_expansion_keeps_earlier_refusal_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        return lambda: raw\n"
        "    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
