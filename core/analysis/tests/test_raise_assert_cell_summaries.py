"""Raise and assert cells are lexical facts, not exception or path proofs."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<raise-assert-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["raise raw", "raise Exception() from raw", "assert raw",
                                  "assert True, raw", "assert (lambda: raw)",
                                  "raise (lambda: raw)"],
                         ids=["raise-value", "raise-cause", "assert-test", "assert-message",
                              "assert-lambda", "raise-lambda"])
def test_returned_function_retains_statement_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {body}\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_assert_helper_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        assert raw\n"
        "        return raw\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [
    ("", "raise"), ("", "assert True"), ("raw=0", "raise raw"),
    ("", "assert raw\n        if False:\n            raw = 0"),
], ids=["bare-raise", "constant-assert", "parameter", "unreachable-binding"])
def test_statement_controls_do_not_capture_outer_cell(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested({header}):\n        {body}\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


def test_unsupported_later_statement_invalidates_capture():
    assert _bounded_body_expression_loads(ast.parse("assert raw\nimport module").body) is None


def test_scoped_annotation_statement_stays_excluded():
    assert _bounded_body_expression_loads(ast.parse("value: (lambda: raw)\nreturn 0").body) is None


def test_assert_message_write_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    assert True, (tmp := raw)\n    def nested():\n"
        "        assert raw\n        return 0\n    return nested()\n"
    )["handle"]
    assert result.summary_unknown_reason == "assertion message conditionally assigns an enclosing-frame name"


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        assert raw\n"
        "        return 0\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
