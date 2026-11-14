"""Bounded linear local-function bodies can retain enclosing cells."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<linear-body-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def test_assignment_return_helper_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        value = raw\n        return value\n"
        "    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize(
    "body", ["value = raw\n        return 0", "raw\n        return 0", "value = raw",
             "return 0\n        value = raw"],
    ids=["constant-return", "unused-read", "no-return", "unreachable-read"],
)
def test_returned_function_object_retains_linear_body_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {body}\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


@pytest.mark.parametrize(
    "body", ["raw = 0\n        return raw", "return raw\n        raw = 0", "pass\n        return 0"],
    ids=["local-shadow", "unreachable-binding", "no-read"],
)
def test_complete_own_bindings_prevent_false_outer_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {body}\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_parameter_default_shadow_keeps_existing_admission():
    result = summaries(
        "def handle(raw):\n    def nested(raw=0):\n        value = raw\n        return value\n"
        "    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


@pytest.mark.parametrize(
    "body", ["global raw\nreturn raw", "value: object = raw\nreturn value",
             "first[(lambda: raw)()] = 0\nreturn 0", "value = raw\nimport module"],
    ids=["global", "annotation", "scoped-target", "later-import"],
)
def test_unsupported_statement_invalidates_complete_new_scan(body):
    assert _bounded_body_expression_loads(ast.parse(body).body) is None


def test_keyword_expansion_keeps_earlier_refusal_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        value = raw\n        return value\n"
        "    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
