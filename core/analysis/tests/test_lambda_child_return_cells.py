"""Child return lambdas retain cells according to nested lexical scopes."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<lambda-child-return>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("expression", ["lambda: raw", "lambda raw=raw: raw",
                                       "lambda: (lambda: raw)", "wrap(lambda: raw)",
                                       "(lambda raw: raw, raw)"],
                         ids=["body", "default", "nested", "call", "shadow-restoration"])
def test_returned_function_retains_lambda_return_cell(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child():\n"
        f"            return {expression}\n        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_lambda_child_return_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            return lambda: raw\n        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("expression", ["lambda raw: raw", "lambda raw, /: raw", "lambda *, raw: raw",
                                       "lambda *raw: raw", "lambda **raw: raw",
                                       "lambda raw: (lambda: raw)"],
                         ids=["positional", "posonly", "kwonly", "vararg", "kwarg", "nested-shadow"])
def test_lambda_parameters_mask_outer_cell(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child():\n"
        f"            return {expression}\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


def test_child_parameter_masks_lambda_capture():
    result = summaries(
        "def handle(raw):\n    def nested():\n        def child(raw):\n"
        "            return lambda: raw\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("expression", ["lambda: [raw for slots[(lambda: raw)()] in ()]", "lambda: (raw := 0)",
                                       "lambda: (lambda value=[raw for slots[(lambda: raw)()] in ()]: value)"],
                         ids=["comprehension", "assignment-expression", "nested-default"])
def test_unsupported_lambda_return_invalidates_complete_body(expression):
    source = f"raw\ndef child():\n return {expression}"
    assert _bounded_body_expression_loads(ast.parse(source).body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child():\n"
        "            return lambda: raw\n        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
