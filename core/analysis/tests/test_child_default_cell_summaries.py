"""Child defaults retain enclosing cells before child parameter binding."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<child-default-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("header,expression", [("value=raw", "value"), ("raw=raw", "raw"),
                                              ("*, value=raw", "value"),
                                              ("value=wrap(raw)", "value")],
                         ids=["positional", "shadow-default", "keyword", "call-expression"])
def test_returned_function_retains_default_cell(header, expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({header}):\n"
        f"            return {expression}\n        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


@pytest.mark.parametrize("prefix", ["", "async "], ids=["ordinary", "async"])
def test_bare_child_return_still_retains_default_cell(prefix):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {prefix}def child(value=raw):\n"
        "            return\n        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_child_default_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child(value=raw):\n"
        "            return value\n        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


def test_constant_child_default_does_not_capture_outer_cell():
    result = summaries(
        "def handle(raw):\n    def nested():\n        def child(raw=0):\n"
        "            return raw\n        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


def test_enclosing_unreachable_binding_masks_default_cell():
    result = summaries(
        "def handle(raw):\n    def nested():\n        def child(value=raw):\n"
        "            return value\n        if False:\n            raw = 0\n"
        "        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("header", ["first=raw, second=[raw for item in ()]", "first=raw, *, second=[raw for item in ()]"],
                         ids=["positional", "keyword"])
def test_unsupported_later_default_invalidates_complete_body(header):
    source = f"raw\ndef child({header}):\n return first"
    assert _bounded_body_expression_loads(ast.parse(source).body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child(value=raw):\n"
        "            return value\n        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
