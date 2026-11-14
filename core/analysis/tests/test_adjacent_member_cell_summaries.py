"""Direct member reads retain the enclosing cell in adjacent local functions."""

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<adjacent-member-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("definition", ["def", "async def"])
@pytest.mark.parametrize("returned", ["nested", "nested()"])
def test_adjacent_member_cell_refuses_known_summary(definition, returned):
    result = summaries(
        f"def handle(raw):\n    {definition} nested():\n        return raw.value\n"
        f"    return {returned}\n"
    )["handle"]
    assert result.summary_unknown
    assert "unmodelled enclosing cell" in result.summary_unknown_reason


def test_member_cell_helper_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        return raw.value\n"
        "    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("signature, actual", [("raw", "0"), ("raw=0", "")])
def test_parameter_shadow_is_not_an_enclosing_member_cell(signature, actual):
    result = summaries(
        f"def handle(raw):\n    def nested({signature}):\n        return raw.value\n"
        f"    return nested({actual})\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_unused_member_cell_function_keeps_existing_admission():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return raw.value\n    return 0\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_member_cell_keyword_expansion_preserves_earlier_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        return raw.value\n"
        "    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
