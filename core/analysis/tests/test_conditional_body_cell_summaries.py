"""Conditional local-function reads retain cells without claiming branch feasibility."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<conditional-body-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def test_conditional_return_helper_keeps_caller_raw_flow():
    result = summaries(
        'import html\ndef helper(raw):\n    def nested():\n        if raw:\n'
        '            return raw\n        return ""\n    return nested()\n'
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize(
    "body", ["if raw:\n            return 0\n        return 0",
             "if True:\n            if raw:\n                return 0\n        return 0",
             "if False:\n            raw\n        return 0"],
    ids=["condition", "nested-condition", "dead-read"],
)
def test_returned_function_retains_conditional_body_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {body}\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_assignment_in_branch_is_an_own_binding_throughout_function():
    result = summaries(
        "def handle(raw):\n    def nested():\n        raw\n        if True:\n"
        "            raw = 0\n        return raw\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_default_parameter_shadow_keeps_existing_admission():
    result = summaries(
        "def handle(raw):\n    def nested(raw=0):\n        if raw:\n"
        "            return raw\n        return 0\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


@pytest.mark.parametrize(
    "body", ["if True:\n global raw\nreturn raw", "if True:\n import value\nreturn raw",
             "raw\nif False:\n class Value:\n  pass\nreturn 0"],
    ids=["nested-global", "nested-import", "later-class"],
)
def test_declaration_anywhere_invalidates_new_statement_scan(body):
    assert _bounded_body_expression_loads(ast.parse(body).body) is None


def test_keyword_expansion_keeps_earlier_refusal_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        if raw:\n            return raw\n"
        "        return 0\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
