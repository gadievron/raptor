"""Dotted pattern expressions expose cells without attribute or matching proof."""

import ast
from textwrap import indent

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<dotted-match-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def source_for(pattern, child=False, header=""):
    body = f"match 0:\n case {pattern}:\n  return 0\n"
    if child:
        body = f"def child({header}):\n" + indent(body, " ") + "return child\n"
        header = ""
    return f"def handle(raw):\n    def nested({header}):\n" + indent(body, "        ") + "    return nested\n"


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("pattern", ["raw.member", "raw.member.deep", "{raw.key: _}", "{0: raw.member}", "[raw.member]", "0 | raw.member", "Value(raw.member)", "{raw.key: Value(raw.member)}"],
                         ids=["value", "deep-value", "key", "mapping-value", "sequence", "or", "class-value", "combined"])
def test_dotted_pattern_retains_expression_cell(pattern, child):
    assert summaries(source_for(pattern, child))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("pattern", ["raw.member", "{raw.key: _}"], ids=["value", "key"])
def test_dotted_pattern_keeps_caller_raw_flow(pattern, child):
    source = source_for(pattern, child).replace("def handle(raw):", "def helper(raw):").replace("    return nested\n", "    return nested()\n")
    source = "import html\n" + source + "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    result = summaries(source)
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_dotted_pattern_parameter_masks_outer_cell(child):
    assert not summaries(source_for("{raw.key: _}", child, "raw"))["handle"].summary_unknown


def test_dotted_attribute_name_is_not_an_enclosing_name_read():
    assert not summaries(source_for("Other.raw"))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("pattern", ["-1.5", "{1+2j: _}", "{raw.key: value}", "Value(member=value)", "[*values]"],
                         ids=["unary", "compound-key", "mapping-capture", "class-capture", "star-capture"])
def test_unsupported_dotted_tree_invalidates_complete_scan(pattern, child):
    tree = ast.parse(source_for(pattern, child))
    assert _bounded_body_expression_loads(tree.body[0].body[0].body) is None


def test_later_case_invalidates_complete_dotted_reads():
    body = "match 0:\n case raw.member:\n  pass\n case Value(value):\n  return value"
    assert _bounded_body_expression_loads(ast.parse(body).body) is None


def test_dotted_pattern_keeps_capture_priority():
    source = source_for("raw.member").replace("    def nested():", "    match raw:\n        case value:\n            pass\n    def nested():")
    assert summaries(source)["handle"].summary_unknown_reason == "pattern capture value transfer is not modelled"
