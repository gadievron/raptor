"""Bounded comprehension reads distinguish captured cells from target bindings."""

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<comprehension-scoped-cell>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize(
    "expression",
    ["[raw for item in (0,)]", "{raw for item in (0,)}", "{raw:0 for item in (0,)}",
     "{0:raw for item in (0,)}", "(raw for item in (0,))", "[0 for item in (0,) if raw]",
     "[0 for item in (0,) for other in raw]"],
    ids=["list-body", "set-body", "dict-key", "dict-value", "generator-body", "filter", "later-iterable"],
)
def test_scoped_comprehension_read_refuses_known_summary(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested()\n"
    )["handle"]
    assert result.summary_unknown
    assert "unmodelled enclosing cell" in result.summary_unknown_reason


def test_list_body_helper_keeps_caller_raw_flow():
    result = summaries(
        "import html\ndef helper(raw):\n    def nested():\n        return [raw for item in (0,)]\n"
        "    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)[0]\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)
    assert not _param_cleanly_sanitized(result["handle"], 0, {"html.escape"})


@pytest.mark.parametrize(
    "expression",
    ["[raw for raw in ()]", "[raw for item in () for raw in ()]",
     "[0 for item in () if raw for raw in ()]"],
    ids=["target-body", "later-target-body", "later-target-filter"],
)
def test_all_comprehension_targets_shadow_enclosing_names(expression):
    result = summaries(
        f"def handle(raw):\n    def nested():\n        return {expression}\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_nested_default_parameter_shadow_keeps_existing_admission():
    result = summaries(
        "def handle(raw):\n    def nested(raw=0):\n        return [raw for item in (0,)]\n"
        "    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_non_name_target_keeps_existing_first_iterable_refusal():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return [0 for first, second in raw]\n"
        "    return nested()\n"
    )["handle"]
    assert result.summary_unknown


def test_keyword_expansion_keeps_earlier_refusal_reason():
    result = summaries(
        "def handle(raw):\n    def nested(**unused):\n        return [raw for item in (0,)]\n"
        "    return nested(**{})\n"
    )["handle"]
    assert result.summary_unknown_reason == "forwards **kwargs"
