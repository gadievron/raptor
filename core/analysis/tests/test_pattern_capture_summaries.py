"""Pattern definitions need subject-to-capture value transfer."""

import pytest

from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<pattern-capture-fixture>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("pattern,value", [
    ("value", "value"),
    ("[value]", "value"),
    ("[*rest]", "rest"),
    ('{"key": value}', "value"),
    ("{**rest}", "rest"),
    ("Record(value)", "value"),
    ("[value] | (value,)", "value"),
    ("_ as value", "value"),
])
def test_pattern_captures_refuse_a_known_summary(pattern, value):
    result = summaries(
        f"def handle(raw):\n    match raw:\n        case {pattern}:\n            return {value}\n"
    )["handle"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == "pattern capture value transfer is not modelled"


def test_capture_helper_wrapper_retains_input_flow():
    result = summaries(
        "def helper(raw):\n    match raw:\n        case value:\n            return value\n"
        "def handle(raw):\n    return helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)


@pytest.mark.parametrize("pattern", ["_", "None", "[1]", '{"key": 1}'])
def test_noncapturing_patterns_keep_direct_input_flow(pattern):
    result = summaries(
        f"def handle(raw):\n    match raw:\n        case {pattern}:\n            pass\n    return raw\n"
    )["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)


def test_guard_assignment_without_pattern_capture_keeps_existing_flow():
    result = summaries(
        "def handle(raw):\n    match raw:\n"
        "        case _ if (value := raw):\n            return value\n"
    )["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)


def test_nested_match_capture_does_not_poison_outer_frame():
    result = summaries(
        "def handle(raw):\n    def nested():\n        match raw:\n"
        "            case value:\n                return value\n    return raw\n"
    )["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)
