"""Generator iteration outputs cannot use ordinary return-only summaries."""

import pytest

from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<generator-summary-fixture>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", ["yield raw", "yield from raw", "yield raw\n    return 0"])
def test_generator_outputs_refuse_ordinary_return_summary(body):
    result = summaries(f"def stream(raw):\n    {body}\n")["stream"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == "generator iteration outputs are not modelled"


def test_next_wrapper_preserves_the_input_flow_from_unknown_generator():
    result = summaries(
        "def stream(raw):\n    yield raw\n\n"
        "def handle(raw):\n    return next(stream(raw))\n"
    )
    assert result["stream"].summary_unknown
    assert result["handle"].param_taints_return(0)


def test_async_generator_is_also_unknown():
    result = summaries("async def stream(raw):\n    yield raw\n")["stream"]
    assert result.summary_unknown


@pytest.mark.parametrize("definition", [
    "def nested():\n        yield raw",
    "nested = lambda: (yield raw)",
])
def test_nested_generator_body_does_not_poison_ordinary_outer_return(definition):
    result = summaries(f"def handle(raw):\n    {definition}\n    return raw\n")["handle"]
    assert not result.summary_unknown
    assert (0, "", -1) in result.return_effects


def test_yield_in_nested_definition_default_belongs_to_outer_generator():
    result = summaries(
        "def handle(raw):\n"
        "    def nested(value=(yield raw)):\n        return value\n"
        "    return 0\n"
    )["handle"]
    assert result.summary_unknown


def test_coroutine_without_yield_keeps_existing_summary():
    result = summaries("async def handle(raw):\n    return raw\n")["handle"]
    assert not result.summary_unknown
    assert (0, "", -1) in result.return_effects
