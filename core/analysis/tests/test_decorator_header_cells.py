"""Decorator expressions retain parent cells without granting wrapper identity."""

import ast
from textwrap import indent

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _bounded_body_expression_loads,
    _detect_summary_unknown,
    build_taint_summaries,
)


def summaries(source):
    compile(source, "<decorator-header-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def source_for(decorator, deep=False, parent_header="", child_header="", body="return 0"):
    decorated = f"@{decorator}\ndef decorated({child_header}):\n" + indent(body, " ") + "\nreturn decorated\n"
    if deep:
        decorated = f"def child({parent_header}):\n" + indent(decorated, " ") + "return child\n"
        parent_header = ""
    return f"def handle(raw):\n    def nested({parent_header}):\n" + indent(decorated, "        ") + "    return nested\n"


@pytest.mark.parametrize("deep", [False, True], ids=["child", "deeper"])
@pytest.mark.parametrize("decorator", ["raw", "raw.member", "registry(raw)", "factory(lambda: raw)", "(tmp := raw)"],
                         ids=["name", "attribute", "call", "lambda", "parent-walrus-read"])
def test_decorator_header_retains_parent_cell(decorator, deep):
    assert summaries(source_for(decorator, deep))["handle"].summary_unknown


@pytest.mark.parametrize("deep", [False, True], ids=["child", "deeper"])
def test_decorator_header_keeps_caller_raw_flow(deep):
    source = source_for("raw", deep).replace("def handle(raw):", "def helper(raw):").replace("    return nested\n", "    return nested()\n")
    source = "import html\n" + source + "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    result = summaries(source)
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("deep", [False, True], ids=["child", "deeper"])
def test_child_parameter_does_not_mask_parent_decorator(deep):
    assert summaries(source_for("raw", deep, child_header="raw"))["handle"].summary_unknown


@pytest.mark.parametrize("deep", [False, True], ids=["child", "deeper"])
@pytest.mark.parametrize("decorator,parent_header", [("raw", "raw"), ("(raw := registry)", ""), ("(lambda raw: raw)", ""), ("registry", "")],
                         ids=["parent-parameter", "parent-walrus-binding", "lambda-parameter", "global"])
def test_parent_bindings_and_lambda_scopes_mask_header_reads(decorator, parent_header, deep):
    assert not summaries(source_for(decorator, deep, parent_header))["handle"].summary_unknown


def test_decorated_body_still_supplies_parent_cell_reads():
    assert summaries(source_for("registry", body="return raw"))["handle"].summary_unknown


def test_unsupported_decorator_descendant_invalidates_complete_scan():
    source = source_for("(lambda: [raw for box[[raw for item in ()]] in ()])")
    tree = ast.parse(source)
    assert _bounded_body_expression_loads(tree.body[0].body[0].body) is None


def test_immediate_returned_decorated_definition_guard_is_unchanged():
    source = "def handle(raw):\n    @raw\n    def nested():\n        return 0\n    return nested\n"
    tree = ast.parse(source)
    assert _detect_summary_unknown(tree.body[0]) is None
    assert summaries(source)["handle.nested"].summary_unknown_reason.startswith("decorated with @raw")
