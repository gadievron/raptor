"""Immediately returned local function objects can retain enclosing cells."""

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<returned-function-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("definition", ["def", "async def"])
def test_immediately_returned_bare_cell_refuses_known_summary(definition):
    result = summaries(
        f"def handle(raw):\n    {definition} nested():\n        return raw\n    return nested\n"
    )["handle"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == "returned function retains an unmodelled enclosing cell"


def test_frame_cell_reader_cannot_be_a_clean_sanitizer_sibling():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        return raw\n    return nested\n"
        'def handle(raw):\n    return html.escape(raw) + helper(raw).__closure__[0].cell_contents\n'
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


def test_function_docstring_does_not_hide_bare_cell_return():
    result = summaries(
        'def handle(raw):\n    def nested():\n        "owned docstring"\n'
        '        return raw\n    return nested\n'
    )["handle"]
    assert result.summary_unknown


@pytest.mark.parametrize("definition", ["raw", "*, raw", "*raw", "**raw"])
def test_nested_parameter_shadow_keeps_existing_admission(definition):
    result = summaries(
        f"def handle(raw):\n    def nested({definition}):\n        return raw\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_default_snapshot_keeps_existing_flow():
    result = summaries(
        "def handle(raw):\n    def nested(value=raw):\n        return value\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)


def test_constant_and_unused_helpers_keep_existing_admission():
    for body in ["return nested", "return 0"]:
        source = f"def handle(raw):\n    def nested():\n        return 0\n    {body}\n"
        result = summaries(source)["handle"]
        assert not result.summary_unknown
        assert not result.param_taints_return(0)
    result = summaries(
        "def handle(raw):\n    def nested():\n        return raw\n    return 0\n"
    )["handle"]
    assert not result.summary_unknown


def test_intervening_rebinding_is_outside_adjacent_definition_guard():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return raw\n    nested = 0\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_explicit_nested_global_is_not_an_enclosing_cell():
    result = summaries(
        "def handle(raw):\n    def nested():\n        global raw\n        return raw\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


def test_generic_definition_is_outside_bounded_bare_cell_guard():
    result = summaries(
        "def handle(T):\n    def nested[T]():\n        return T\n    return nested\n"
    )["handle"]
    assert not result.summary_unknown


@pytest.mark.parametrize("prefix,reason", [
    ("    class Record:\n        pass\n", "class namespace value transfer is not modelled"),
    ("    getattr(raw, 'field')\n", "calls getattr"),
])
def test_existing_refusal_reason_keeps_priority(prefix, reason):
    result = summaries(
        "def handle(raw):\n" + prefix
        + "    def nested():\n        return raw\n    return nested\n"
    )["handle"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == reason


def test_constant_valued_captured_cell_is_conservatively_unknown():
    result = summaries(
        "def handle(raw):\n    value = 0\n    def nested():\n        return value\n    return nested\n"
    )["handle"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == "returned function retains an unmodelled enclosing cell"


def test_yielding_definition_default_keeps_generator_refusal_reason():
    result = summaries(
        "def handle(raw):\n    def nested(value=(yield raw)):\n        return raw\n    return nested\n"
    )["handle"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == "generator iteration outputs are not modelled"
