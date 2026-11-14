"""Literal pattern admission records cells without proving comparison or matching."""

import ast
from textwrap import indent

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<literal-match-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def source_for(pattern, child=False, header="", suffix=""):
    body = f"match 0:\n case {pattern}:\n  return raw\n" + suffix
    if child:
        body = f"def child({header}):\n" + indent(body, " ") + "return child\n"
        header = ""
    return f"def handle(raw):\n    def nested({header}):\n" + indent(body, "        ") + "    return nested\n"


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("pattern", ["None", "True", "False", "0", "1.5", "'literal'", "b'literal'", "1j"],
                         ids=["none", "true", "false", "integer", "float", "string", "bytes", "imaginary-constant"])
def test_literal_pattern_retains_body_cell(pattern, child):
    assert summaries(source_for(pattern, child))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_literal_pattern_keeps_caller_raw_flow(child):
    source = source_for("0", child).replace("def handle(raw):", "def helper(raw):").replace("    return nested\n", "    return nested()\n")
    source = "import html\n" + source + "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    result = summaries(source)
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_literal_pattern_parameter_masks_outer_cell(child):
    assert not summaries(source_for("0", child, "raw"))["handle"].summary_unknown


@pytest.mark.parametrize("pattern", ["-1", "-1j", "1+2j", "raw.member", "value", "0 | 1", "[value]"],
                         ids=["negative", "negative-imaginary", "complex-expression", "dotted", "capture", "or", "sequence"])
def test_other_pattern_shapes_stay_excluded(pattern):
    source = source_for(pattern)
    assert _bounded_body_expression_loads(ast.parse(source).body[0].body[0].body) is None


def test_later_case_invalidates_complete_literal_scan():
    body = "match raw:\n case 0:\n  raw\n case value:\n  return value"
    assert _bounded_body_expression_loads(ast.parse(body).body) is None


def test_literal_match_keeps_capture_priority():
    source = source_for("0").replace("    def nested():", "    match raw:\n        case value:\n            pass\n    def nested():")
    assert summaries(source)["handle"].summary_unknown_reason == "pattern capture value transfer is not modelled"
