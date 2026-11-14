"""Augmented stores expose lexical cells without operator execution."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<augmented-body-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["raw.member += 1", "slots[raw] += 1",
                                  "value = 0\n        value += raw"],
                         ids=["member", "index", "rhs"])
def test_returned_function_retains_augmented_store_cell(body):
    result = summaries(
        f"def handle(raw, slots):\n    def nested():\n        {body}\n"
        "        return 0\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_augmented_helper_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        value = 0\n"
        "        value += raw\n        return value\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [
    ("", "raw += 1"), ("raw=0", "raw.member += 1"),
    ("", "raw.member += 1\n        if False:\n            raw = 0"),
], ids=["bare-local", "parameter", "unreachable-binding"])
def test_own_binding_masks_augmented_target_cell(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested({header}):\n        {body}\n"
        "        return 0\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("target", ["slots[(lambda: raw)()]", "slots[(raw := 0)]"],
                         ids=["lambda", "walrus"])
def test_unsupported_augmented_target_invalidates_complete_body(target):
    assert _bounded_body_expression_loads(ast.parse(f"raw\n{target} += 1").body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        raw.member += 1\n"
        "        return 0\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
