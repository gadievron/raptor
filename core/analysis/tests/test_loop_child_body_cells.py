"""Child loop cells are lexical facts rather than iteration or path proofs."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<loop-child-body>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["for item in raw:\n                return item\n            return 0",
                                  "while raw:\n                return 0\n            return 0",
                                  "for item in ():\n                raw\n            return 0",
                                  "for item in ():\n                pass\n            else:\n                return raw",
                                  "while True:\n                raw\n                break\n            return 0",
                                  "for item in ():\n                raw\n                continue\n            return 0"],
                         ids=["iterable", "condition", "body", "else", "break", "continue"])
def test_returned_function_retains_child_loop_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child():\n            {body}\n"
        "        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_async_child_loop_is_metadata_only():
    result = summaries(
        "def handle(raw):\n    def nested():\n        async def child():\n"
        "            async for item in raw:\n                return item\n            return 0\n"
        "        return child\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_loop_child_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        def child():\n"
        "            for item in raw:\n                return item\n            return 0\n"
        "        return child\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [("raw", "while raw:\n                return raw\n            return 0"),
                                       ("", "for raw in ():\n                pass\n            return raw"),
                                       ("", "while False:\n                raw = 0\n            return raw")],
                         ids=["parameter", "loop-target", "unreachable-binding"])
def test_whole_child_bindings_mask_loop_reads(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        def child({header}):\n            {body}\n"
        "        return child\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("body", ["for obj[(lambda: raw)()] in ():\n  pass",
                                  "while raw:\n  break\n  global unsupported",
                                  "for item in ():\n  pass\n else:\n  global other"],
                         ids=["indirect-target", "declaration-after-break", "else-global"])
def test_unsupported_child_loop_invalidates_complete_body(body):
    assert _bounded_body_expression_loads(ast.parse("raw\ndef child():\n " + body).body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        def child():\n"
        "            while raw:\n                return raw\n            return 0\n"
        "        return child\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
