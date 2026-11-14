"""Linear child bodies retain cells without proving assignment or return values."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<linear-child-body>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["value = raw\n            return value",
                                  "first = second = raw\n            return first",
                                  "raw\n            return 0", "raw\n            pass"],
                         ids=["assignment", "chained", "unused-read", "no-return"])
def test_returned_function_retains_linear_child_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child():\n            {body}\n"
        "        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_linear_child_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            value = raw\n            return value\n        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [("raw", "value = raw\n            return value"),
                                       ("", "raw = 0\n            return raw"),
                                       ("", "return raw\n            raw = 0"),
                                       ("", "pass\n            return")],
                         ids=["parameter", "own-binding", "unreachable-binding", "bare-return"])
def test_child_own_bindings_mask_outer_cell(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({header}):\n            {body}\n"
        "        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("body", ["raw\n import module", "if raw:\n  return raw",
                                  "for item in raw:\n  return item", "global raw\n return raw",
                                  "def deeper():\n  return raw", "raw.member = 0\n return 0"],
                         ids=["import", "branch", "loop", "global", "nested-definition", "indirect-target"])
def test_unsupported_child_statement_invalidates_complete_body(body):
    source = "raw\ndef child():\n " + body
    assert _bounded_body_expression_loads(ast.parse(source).body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child():\n"
        "            value = raw\n            return value\n        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
