"""An immediately called bare-cell local function needs a closure model."""

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<adjacent-cell-call>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("definition", ["def", "async def"])
def test_adjacent_zero_argument_cell_call_refuses_known_summary(definition):
    result = summaries(
        f"def handle(raw):\n    {definition} nested():\n        return raw\n    return nested()\n"
    )["handle"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == "returned local call depends on an unmodelled enclosing cell"


def test_unknown_cell_call_helper_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        return raw\n    return nested()\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize("definition", ["raw=0", "*, raw=0"])
def test_nested_default_parameter_shadow_is_not_an_enclosing_cell(definition):
    result = summaries(
        f"def handle(raw):\n    def nested({definition}):\n        return raw\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_evaluated_default_snapshot_keeps_existing_flow():
    result = summaries(
        "def handle(raw):\n    def nested(value=raw):\n        return value\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)


def test_constant_body_call_remains_admitted():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return 0\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_intervening_callable_rebinding_stays_outside_adjacent_guard():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return raw\n"
        "    nested = lambda: 0\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_constant_valued_captured_cell_call_is_conservatively_unknown():
    result = summaries(
        "def handle(raw):\n    value = 0\n    def nested():\n        return value\n    return nested()\n"
    )["handle"]
    assert result.summary_unknown


def test_existing_generator_refusal_keeps_priority_for_returned_call():
    result = summaries(
        "def handle(raw):\n    def nested(value=(yield raw)):\n        return raw\n    return nested()\n"
    )["handle"]
    assert result.summary_unknown_reason == "generator iteration outputs are not modelled"


@pytest.mark.parametrize(
    "signature, actual",
    [("unused", "0"), ("*, unused", "unused=0"), ("*unused", "*[0]")],
    ids=["positional", "keyword", "starred"],
)
def test_arguments_do_not_remove_an_adjacent_captured_cell(signature, actual):
    result = summaries(
        f"import html\ndef helper(raw):\n    def nested({signature}):\n"
        f"        return raw\n    return nested({actual})\n"
        "def handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["helper"].summary_unknown_reason == (
        "returned local call depends on an unmodelled enclosing cell"
    )
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


def test_explicit_argument_shadow_is_not_a_captured_cell():
    result = summaries(
        "def handle(raw):\n    def nested(raw):\n        return raw\n    return nested(0)\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_keyword_expansion_keeps_earlier_refusal_priority():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        return raw\n"
        "    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
