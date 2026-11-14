"""Direct returned bare-name lambdas retain enclosing cells, not snapshots."""

import pytest

from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<returned-lambda-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", [
    "return lambda: raw",
    "value = raw\nreturn lambda: value",
    "value = 0\nreturn lambda: value",
])
def test_returned_bare_enclosing_cell_refuses_known_summary(body):
    source = "def handle(raw):\n" + "".join(f"    {line}\n" for line in body.splitlines())
    result = summaries(source)["handle"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == "returned lambda retains an unmodelled enclosing cell"


def test_unknown_cell_helper_preserves_wrapper_input_flow():
    result = summaries(
        "def helper(raw):\n    return lambda: raw\n"
        "def handle(raw):\n    return helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)


def test_shadowed_return_does_not_hide_a_capturing_return():
    result = summaries(
        "def handle(raw, flag):\n    if flag:\n        return lambda: raw\n"
        "    return lambda raw: raw\n"
    )["handle"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == "returned lambda retains an unmodelled enclosing cell"


@pytest.mark.parametrize("expression", [
    "lambda raw: raw",
    "lambda *, raw: raw",
    "lambda *raw: raw",
    "lambda **raw: raw",
    "lambda: 0",
])
def test_parameter_shadow_and_constant_lambdas_keep_known_summary(expression):
    result = summaries(f"def handle(raw):\n    return {expression}\n")["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_default_snapshot_keeps_existing_flow():
    result = summaries("def handle(raw):\n    return lambda value=raw: value\n")["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)


def test_unused_capturing_lambda_does_not_poison_outer_summary():
    result = summaries("def handle(raw):\n    unused = lambda: raw\n    return 0\n")["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_returned_lambda_in_unused_nested_body_does_not_poison_outer():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return lambda: raw\n    return raw\n"
    )["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)
