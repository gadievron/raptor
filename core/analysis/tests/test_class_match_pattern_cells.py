"""Class-pattern expressions retain cells without executing class matching."""

import ast
from textwrap import indent

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<class-match-cell>", "exec", dont_inherit=True)
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
@pytest.mark.parametrize("pattern", ["raw()", "raw.Value()", "Value(raw())", "Value(member=raw())", "Value([raw()])", "{0: raw()}"],
                         ids=["name", "dotted", "positional", "keyword-value", "sequence", "mapping"])
def test_class_pattern_retains_expression_cell(pattern, child):
    assert summaries(source_for(pattern, child))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_class_pattern_keeps_caller_raw_flow(child):
    source = source_for("raw()", child).replace("def handle(raw):", "def helper(raw):").replace("    return nested\n", "    return nested()\n")
    source = "import html\n" + source + "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    result = summaries(source)
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
def test_class_pattern_parameter_masks_outer_cell(child):
    assert not summaries(source_for("raw()", child, "raw"))["handle"].summary_unknown


@pytest.mark.parametrize("pattern", ["Value(raw=_)", "Value('raw')", "Value()"],
                         ids=["keyword-attribute-string", "literal-string", "global-class"])
def test_class_attribute_strings_and_globals_are_not_outer_reads(pattern):
    assert not summaries(source_for(pattern))["handle"].summary_unknown


@pytest.mark.parametrize("child", [False, True], ids=["root", "child"])
@pytest.mark.parametrize("pattern", ["Value(value)", "Value(member=value)", "(Value(-1.5)) as value", "(Value({1+2j: _})) as value", "(Value(-1)) as value", "Value([*values])"],
                         ids=["capture", "keyword-capture", "unary-float-value-capture", "compound-key-capture", "unary-value-capture", "named-star"])
def test_unsupported_class_child_invalidates_complete_scan(pattern, child):
    tree = ast.parse(source_for(pattern, child))
    assert _bounded_body_expression_loads(tree.body[0].body[0].body) is None


def test_later_case_invalidates_complete_class_reads():
    body = "match 0:\n case raw():\n  pass\n case Value(value):\n  return value"
    assert _bounded_body_expression_loads(ast.parse(body).body) is None


def test_class_pattern_keeps_capture_priority():
    source = source_for("raw()").replace("    def nested():", "    match raw:\n        case value:\n            pass\n    def nested():")
    assert summaries(source)["handle"].summary_unknown_reason == "pattern capture value transfer is not modelled"
