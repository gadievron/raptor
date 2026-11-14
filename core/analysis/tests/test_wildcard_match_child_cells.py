"""Child wildcard matches expose cells without executing subjects or patterns."""

import ast
from textwrap import indent

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<child-wildcard-match>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def child_source(body, header=""):
    return (f"def handle(raw):\n    def nested():\n        def child({header}):\n"
            + indent(body, "            ") + "\n        return child\n    return nested\n")


@pytest.mark.parametrize("body", [
    "match raw:\n case _:\n  return 0",
    "match 0:\n case _ if raw:\n  return 0",
    "match 0:\n case _:\n  return raw",
    "match 0:\n case _ if False:\n  raw\n case _:\n  return 0",
], ids=["subject", "guard", "body", "unreachable-body"])
def test_returned_function_retains_match_child_cell(body):
    assert summaries(child_source(body))["handle"].summary_unknown


def test_match_child_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            match 0:\n                case _:\n                    return raw\n"
        "        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [
    ("", "match 0:\n case _:\n  return 0"),
    ("raw", "match raw:\n case _:\n  return 0"),
    ("", "match raw:\n case _:\n  if False:\n   raw = 0"),
], ids=["constant", "parameter", "unreachable-binding"])
def test_whole_child_bindings_mask_match_reads(header, body):
    assert not summaries(child_source(body, header))["handle"].summary_unknown


@pytest.mark.parametrize("pattern", ["value", "raw.member", "[value, _]", "{}", "Value()", "0 | 1"],
                         ids=["capture", "value", "sequence", "mapping", "class", "or"])
def test_unsupported_child_pattern_invalidates_complete_scan(pattern):
    source = child_source(f"match 0:\n case _ if False:\n  raw\n case {pattern}:\n  return raw")
    assert _bounded_body_expression_loads(ast.parse(source).body[0].body[0].body) is None


@pytest.mark.parametrize("body", ["match raw:\n case _:\n  global other",
                                  "match (yield raw):\n case _:\n  return 0"],
                         ids=["unsupported-body", "unsupported-subject"])
def test_unsupported_child_match_invalidates_complete_scan(body):
    source = child_source(body)
    assert _bounded_body_expression_loads(ast.parse(source).body[0].body[0].body) is None


def test_outer_capture_keeps_prior_reason():
    source = child_source("match raw:\n case _:\n  return raw")
    source = source.replace("    def nested():", "    match raw:\n        case value:\n            pass\n    def nested():")
    assert summaries(source)["handle"].summary_unknown_reason == "pattern capture value transfer is not modelled"
