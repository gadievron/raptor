"""Wildcard match cells are lexical facts without pattern or path authority."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<wildcard-match-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", [
    "match raw:\n            case _:\n                return 0",
    "match 0:\n            case _ if raw:\n                return 0",
    "match 0:\n            case _:\n                return raw",
    "match 0:\n            case _ if False:\n                raw\n            case _:\n                return 0",
], ids=["subject", "guard", "body", "unreachable-body"])
def test_returned_function_retains_wildcard_match_cell(body):
    result = summaries(f"def handle(raw):\n    def nested():\n        {body}\n    return nested\n")["handle"]
    assert result.summary_unknown


def test_wildcard_match_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        match 0:\n"
        "            case _:\n                return raw\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [
    ("", "match 0:\n            case _:\n                return 0"),
    ("raw", "match raw:\n            case _:\n                return 0"),
    ("", "match raw:\n            case _:\n                if False:\n                    raw = 0"),
], ids=["constant", "parameter", "unreachable-binding"])
def test_whole_function_bindings_mask_match_reads(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested({header}):\n        {body}\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("pattern", ["value", "raw.member", "[value, _]", "{0: value}", "Value()", "0 | raw.member"],
                         ids=["capture", "value", "sequence", "mapping", "class", "or"])
def test_unsupported_pattern_invalidates_complete_scan(pattern):
    body = f"raw\nmatch 0:\n case _ if False:\n  raw\n case {pattern}:\n  return raw"
    assert _bounded_body_expression_loads(ast.parse(body).body) is None


def test_unsupported_case_body_invalidates_complete_scan():
    body = "raw\nmatch 0:\n case _ if False:\n  raw\n case _:\n  global other"
    assert _bounded_body_expression_loads(ast.parse(body).body) is None


def test_capturing_child_match_stays_excluded():
    body = "def child():\n match raw:\n  case value:\n   return raw"
    assert _bounded_body_expression_loads(ast.parse(body).body) is None


def test_outer_capture_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    match raw:\n        case value:\n            pass\n"
        "    def nested():\n        match raw:\n            case _:\n                return raw\n"
        "    return nested()\n"
    )["handle"]
    assert result.summary_unknown_reason == "pattern capture value transfer is not modelled"


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        match raw:\n"
        "            case _:\n                return raw\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
