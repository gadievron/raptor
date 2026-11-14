"""Indirect stores retain lexical cells without proving stored value flow."""

import ast

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<indirect-body-target>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", [
    "raw.member = 0", "slots[raw] = 0",
    "for raw.member in ():\n            pass",
    "for slots[raw] in ():\n            pass",
    "first, raw.member = ()", "raw.member = first = 0",
], ids=["assign-member", "assign-index", "for-member", "for-index", "unpacking", "chained"])
def test_returned_object_retains_target_cells(body):
    result = summaries(
        f"def handle(raw, slots):\n    def nested():\n        {body}\n"
        "        return 0\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


@pytest.mark.parametrize("target", ["raw.member", "slots[raw]"], ids=["member", "index"])
def test_async_loop_target_cells_are_metadata_only(target):
    result = summaries(
        f"def handle(raw, slots):\n    async def nested():\n        async for {target} in ():\n"
        "            pass\n        return 0\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_direct_target_capture_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        raw.member = 0\n"
        "        return 0\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [
    ("raw=0", "raw.member = 0"),
    ("", "for raw, raw.member in ():\n            pass"),
    ("", "raw.member = 0\n        if False:\n            raw = 0"),
], ids=["parameter", "other-target", "unreachable-binding"])
def test_whole_function_binding_masks_target_read(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested({header}):\n        {body}\n"
        "        return 0\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("target", ["slots[(lambda: (yield raw))()]", "slots[(raw := 0)]"],
                         ids=["lambda", "walrus"])
def test_unsupported_target_invalidates_earlier_capture(target):
    assert _bounded_body_expression_loads(ast.parse(f"raw\n{target} = 0").body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        raw.member = 0\n"
        "        return 0\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
