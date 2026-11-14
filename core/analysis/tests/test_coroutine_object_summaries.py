"""Coroutine frame arguments are retained before the async body executes."""

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<coroutine-object-summary>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["return html.escape(raw)", "return 0"])
def test_coroutine_frame_read_keeps_raw_argument_flow(body):
    result = summaries(
        f"import html\nasync def helper(raw):\n    {body}\n"
        'def handle(raw):\n    return helper(raw).cr_frame.f_locals["raw"]\n'
    )
    assert not result["helper"].summary_unknown
    assert (0, "", -1) in result["helper"].return_effects
    assert (0, "", -1) in result["handle"].return_effects
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


def test_all_formal_parameter_slots_are_retained_even_when_body_is_constant():
    result = summaries(
        "async def helper(first, /, second=0, *rest, key=0, **extra):\n    return 0\n"
    )["helper"]
    assert not result.summary_unknown
    assert set(result.params) == {"first", "second", "rest", "key", "extra"}
    assert result.return_effects == frozenset((pi, "", -1) for pi in range(len(result.params)))


@pytest.mark.parametrize("definition,call", [
    ("raw", "helper(raw)"),
    ("*, raw=0", "helper(raw=raw)"),
    ("*raw", "helper(raw)"),
    ("**raw", "helper(value=raw)"),
])
def test_call_binding_keeps_retained_input(definition, call):
    result = summaries(
        f"async def helper({definition}):\n    return 0\n"
        f"def handle(raw):\n    return {call}\n"
    )["handle"]
    assert result.param_taints_return(0)


def test_async_sanitizer_await_stays_conservative_without_separate_result_model():
    result = summaries(
        "import html\nasync def helper(raw):\n    return html.escape(raw)\n"
        "async def handle(raw):\n    return await helper(raw)\n"
    )
    assert not result["helper"].summary_unknown
    assert (0, "html.escape", 0) in result["helper"].return_effects
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


def test_sync_constant_and_sanitizer_summaries_keep_existing_precision():
    result = summaries(
        "import html\ndef constant(raw):\n    return 0\n"
        "def clean(raw):\n    return html.escape(raw)\n"
    )
    assert not result["constant"].param_taints_return(0)
    assert _param_cleanly_sanitized(result["clean"], 0, {"html.escape"})


def test_unused_nested_async_body_does_not_change_outer_summary():
    result = summaries(
        "import html\ndef handle(raw):\n    async def unused():\n        return raw\n"
        "    return html.escape(raw)\n"
    )["handle"]
    assert _param_cleanly_sanitized(result, 0, {"html.escape"})
