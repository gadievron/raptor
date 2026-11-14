"""Child raise and assertion expressions expose lexical cells without execution."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<raise-assert-child>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["raise raw", "raise Exception() from raw", "assert raw",
                                  "assert True, raw", "assert (lambda: raw)",
                                  "raise (lambda: raw)"],
                         ids=["raise-value", "raise-cause", "assert-test", "assert-message",
                              "assert-lambda", "raise-lambda"])
def test_returned_function_retains_statement_child_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child():\n            {body}\n"
        "        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_assert_child_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            assert raw\n            return raw\n        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [
    ("", "raise"), ("", "assert True"), ("raw", "raise raw"),
    ("", "assert raw\n            if False:\n                raw = 0"),
], ids=["bare-raise", "constant-assert", "parameter", "unreachable-binding"])
def test_whole_child_bindings_mask_statement_reads(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({header}):\n            {body}\n"
        "        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("body", ["assert raw\n global unsupported", "raise (yield [raw for box[[(lambda: (yield raw))() for item in ()]] in ()])"],
                         ids=["later-declaration", "yield-scoped-target"])
def test_unsupported_child_tree_invalidates_complete_body(body):
    assert _bounded_body_expression_loads(ast.parse("raw\ndef child():\n " + body).body) is None


def test_outer_assert_message_write_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    assert True, (tmp := raw)\n    def nested():\n"
        "        def child():\n            assert raw\n        return child\n    return nested()\n"
    )["handle"]
    assert result.summary_unknown_reason == "assertion message conditionally assigns an enclosing-frame name"


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child():\n"
        "            assert raw\n        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
