"""Conditional child reads identify lexical cells without proving branch paths."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<conditional-child-body>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["if raw:\n                return 0\n            return 0",
                                  "if flag:\n                return raw\n            return 0",
                                  "if flag:\n                return 0\n            else:\n                return raw",
                                  "if flag:\n                if raw:\n                    return 0\n            return 0"],
                         ids=["condition", "then", "else", "nested"])
def test_returned_function_retains_conditional_child_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child():\n            {body}\n"
        "        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_conditional_child_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            if raw:\n                return raw\n            return 0\n"
        "        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [("raw", "if raw:\n                return raw\n            return 0"),
                                       ("", "if False:\n                raw = 0\n            return raw"),
                                       ("", "if True:\n                return raw\n                raw = 0\n            return 0")],
                         ids=["parameter", "unreachable-assignment", "after-return-assignment"])
def test_whole_child_bindings_mask_conditional_reads(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({header}):\n            {body}\n"
        "        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("body", ["if raw:\n  import module",
                                  "if raw:\n  return raw\n else:\n  global other",
                                  "if raw:\n  def deeper():\n   return raw",
                                  "if raw:\n  for obj[(lambda: raw)()] in ():\n   pass"],
                         ids=["then-import", "else-global", "nested-definition", "indirect-loop"])
def test_unsupported_child_branch_invalidates_complete_body(body):
    source = "raw\ndef child():\n " + body
    assert _bounded_body_expression_loads(ast.parse(source).body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child():\n"
        "            if raw:\n                return raw\n            return 0\n"
        "        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
