"""Context statements expose lexical cells without entering any context."""


from core.analysis.tests.target_ast_helpers import parse_target_refusal_fixture

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


def summaries(source):
    compile(source, "<context-body-cell>", "exec", dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", [
    "with raw:\n            pass", "with manager:\n            raw",
    "with manager as raw.member:\n            pass",
    "with manager as slots[raw]:\n            pass",
    "with manager as (item, raw.member):\n            pass",
    "with manager, raw:\n            pass", "with (lambda: raw):\n            pass",
], ids=["context", "body", "member-target", "index-target", "unpacking", "multiple", "lambda"])
def test_returned_function_retains_context_cell(body):
    result = summaries(
        f"def handle(raw, slots):\n    def nested():\n        {body}\n"
        "        return 0\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_async_context_cell_is_metadata_only():
    result = summaries(
        "def handle(raw):\n    async def nested():\n        async with raw:\n"
        "            pass\n        return 0\n    return nested\n"
    )["handle"]
    assert result.summary_unknown


def test_context_helper_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        with raw as value:\n"
        "            return value\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("header,body", [
    ("", "with manager as raw:\n            raw"),
    ("", "with raw as item, manager as raw:\n            pass"),
    ("raw=0", "with raw:\n            pass"),
    ("", "with raw:\n            pass\n        if False:\n            raw = 0"),
], ids=["target-shadow", "later-item-shadow", "parameter", "unreachable-binding"])
def test_whole_function_bindings_mask_context_cells(header, body):
    result = summaries(
        f"def handle(raw):\n    def nested({header}):\n        {body}\n"
        "        return 0\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("body", [
    "with manager as slots[_raptor_unsupported_target]:\n pass",
    "with manager as slots[(raw := 0)]:\n pass",
    "with raw:\n global unsupported",
], ids=["synthetic-target", "walrus-target", "body-import"])
def test_unsupported_context_tree_invalidates_earlier_capture(body):
    assert _bounded_body_expression_loads(parse_target_refusal_fixture(f"raw\n{body}").body) is None


def test_keyword_expansion_keeps_prior_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        with raw:\n"
        "            return 0\n    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
