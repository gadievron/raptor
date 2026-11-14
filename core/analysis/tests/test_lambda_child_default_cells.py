"""Lambda defaults retain cells according to each lexical parameter scope."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<lambda-child-default>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("default", ["lambda: raw", "lambda raw=raw: raw",
                                    "lambda: (lambda: raw)", "wrap(lambda: raw)",
                                    "(lambda raw: raw, raw)", "lambda *, value=raw: value"],
                         ids=["body", "own-default", "nested", "call", "shadow-restoration", "kwdefault"])
def test_returned_function_retains_lambda_default_cell(default):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child(value={default}):\n"
        "            return value\n        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_lambda_child_default_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child(value=lambda: raw):\n"
        "            return value\n        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("default", ["lambda raw: raw", "lambda raw, /: raw", "lambda *, raw: raw",
                                    "lambda *raw: raw", "lambda **raw: raw",
                                    "lambda raw: (lambda: raw)"],
                         ids=["positional", "posonly", "kwonly", "vararg", "kwarg", "nested-shadow"])
def test_lambda_parameters_mask_outer_cell(default):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child(value={default}):\n"
        "            return value\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("default", ["lambda: [raw for item in ()]", "lambda: (raw := 0)",
                                    "lambda: (lambda value=[raw for item in ()]: value)"],
                         ids=["comprehension", "assignment-expression", "nested-default"])
def test_unsupported_lambda_descendant_invalidates_complete_body(default):
    source = f"raw\ndef child(value={default}):\n return value"
    assert _bounded_body_expression_loads(ast.parse(source).body) is None


def test_child_return_lambda_stays_outside_body_grammar():
    source = "def child(value=lambda: raw):\n return lambda: raw"
    assert _bounded_body_expression_loads(ast.parse(source).body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child(value=lambda: raw):\n"
        "            return value\n        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
