"""First comprehension iterables read the adjacent function's enclosing cells."""

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<comprehension-iterable-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize(
    "expression",
    ["[0 for item in raw]", "{0 for item in raw}", "{0: 0 for item in raw}",
     "(0 for item in raw)", "[0 for raw in raw]"],
    ids=["list", "set", "dict", "generator", "target-shadow"],
)
def test_first_iterable_cell_keeps_caller_raw_flow(expression):
    result = summaries(
        f"import html\ndef helper(raw):\n    def nested():\n        return {expression}\n"
        "    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


def test_returned_function_object_retains_first_iterable_cell():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return [0 for item in raw]\n"
        "    return nested\n"
    )["handle"]
    assert result.summary_unknown_reason == "returned function retains an unmodelled enclosing cell"


def test_parameter_shadow_is_not_an_enclosing_iterable_cell():
    result = summaries(
        "def handle(raw):\n    def nested(raw=()):\n        return [0 for item in raw]\n"
        "    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_comprehension_target_is_not_an_enclosing_read():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return [raw for raw in ()]\n"
        "    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_unused_comprehension_cell_keeps_existing_admission():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return [0 for item in raw]\n    return 0\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_keyword_expansion_keeps_earlier_refusal_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        return [0 for item in raw]\n"
        "    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
