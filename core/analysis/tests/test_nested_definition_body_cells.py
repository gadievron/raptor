"""Simple nested definitions retain lexical cells without running any body."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<nested-definition-body>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("prefix,ending", [("", "return child"), ("async ", "return child"),
                                          ("", "return 0")],
                         ids=["returned-child", "async-child", "unused-child"])
def test_returned_function_retains_child_body_cell(prefix, ending):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {prefix}def child():\n"
        f"            return raw\n        {ending}\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_nested_definition_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            return raw\n        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("parameters,expression", [("raw", "raw"), ("raw, /", "raw"),
                                                  ("*, raw", "raw"), ("*raw", "raw"),
                                                  ("**raw", "raw"), ("", "child")],
                         ids=["positional", "posonly", "kwonly", "vararg", "kwarg", "recursive-name"])
def test_child_own_parameters_and_name_do_not_capture_outer_cell(parameters, expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({parameters}):\n"
        f"            return {expression}\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


def test_enclosing_unreachable_binding_masks_child_capture():
    result = summaries(
        "def handle(raw):\n    def nested():\n        def child():\n            return raw\n"
        "        if False:\n            raw = 0\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


def test_bare_child_return_contributes_no_reads():
    assert _bounded_body_expression_loads(ast.parse("def child():\n return").body) == frozenset()


@pytest.mark.parametrize("source", [
    "def child(value=[raw for item in ()]):\n return value", "def child(*, value=[raw for item in ()]):\n return value",
    "def child(value: raw):\n return value", "def child() -> raw:\n return 0",
    "@raw\ndef child():\n return 0", "def child[T]():\n return raw",
    "def child():\n return lambda: raw", "def child():\n value = raw\n return value",
], ids=["default", "kwdefault", "parameter-annotation", "return-annotation", "decorator",
        "type-parameter", "scoped-return", "multiple-statements"])
def test_unsupported_child_invalidates_complete_body(source):
    assert _bounded_body_expression_loads(ast.parse(f"raw\n{source}").body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child():\n"
        "            return raw\n        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
