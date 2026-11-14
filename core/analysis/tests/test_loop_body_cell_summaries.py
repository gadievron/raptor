"""Loop-body captures are lexical facts rather than iteration or path proofs."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<loop-body-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize(
    "body", ['for item in raw:\n            return item\n        return ""',
             'while raw:\n            return raw\n        return ""'],
    ids=["for-iterable", "while-condition"],
)
def test_loop_helper_keeps_caller_raw_flow(body):
    result = summaries(
        f"import html\ndef helper(raw):\n    def nested():\n        {body}\n"
        "    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize(
    "body", ["for item in ():\n            pass\n        else:\n            return raw",
             "while True:\n            raw\n            break\n        return 0",
             "for item in ():\n            raw\n            continue\n        return 0"],
    ids=["else-read", "break-read", "continue-read"],
)
def test_returned_function_retains_loop_body_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {body}\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_async_iterator_cell_does_not_require_execution():
    result = summaries(
        "def handle(raw):\n    async def nested():\n        async for item in raw:\n"
        "            return item\n        return 0\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


@pytest.mark.parametrize(
    "body", ["for raw in ():\n            pass\n        return raw",
             "while False:\n            raw = 0\n        return raw"],
    ids=["for-target", "unreachable-assignment"],
)
def test_loop_own_bindings_shadow_outer_cell(body):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        {body}\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


@pytest.mark.parametrize(
    "body", ["for obj[(lambda: (yield raw))()] in ():\n pass\nreturn 0",
             "while False:\n global raw\nreturn raw",
             "for item in ():\n break\n global unsupported\nreturn raw"],
    ids=["indirect-target", "nested-global", "declaration-after-break"],
)
def test_exclusions_invalidate_complete_loop_statement_tree(body):
    assert _bounded_body_expression_loads(ast.parse(body).body) is None


def test_keyword_expansion_keeps_earlier_refusal_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        while raw:\n            return raw\n"
        "        return 0\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
