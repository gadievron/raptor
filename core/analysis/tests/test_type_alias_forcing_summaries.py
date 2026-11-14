"""Deferred type-alias values require a forcing-aware summary contract."""

import ast

import pytest

from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries

pytestmark = pytest.mark.skipif(not hasattr(ast, "TypeAlias"), reason="type statements require Python 3.12+")


def summaries(source):
    compile(source, "<type-alias-summary-fixture>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("value", ["raw", "str(raw)"])
def test_alias_value_access_refuses_an_ordinary_known_summary(value):
    result = summaries(f"def handle(raw):\n    type Alias = {value}\n    return Alias.__value__\n")["handle"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == "type alias deferred values are not modelled"


def test_alias_helper_wrapper_retains_input_flow():
    result = summaries(
        "def helper(raw):\n    type Alias = raw\n    return Alias.__value__\n"
        "def handle(raw):\n    return helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)


def test_unused_alias_is_conservatively_unknown():
    result = summaries("def handle(raw):\n    type Alias = int\n    return raw\n")["handle"]
    assert result.summary_unknown


def test_nested_function_alias_does_not_poison_outer_frame():
    result = summaries(
        "def handle(raw):\n    def nested():\n        type Alias = raw\n"
        "        return Alias.__value__\n    return raw\n"
    )["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)


def test_regular_assignment_keeps_direct_input_flow():
    result = summaries("def handle(raw):\n    Alias = raw\n    return Alias\n")["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)
