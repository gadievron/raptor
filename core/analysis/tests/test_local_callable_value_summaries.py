"""A local callable value can carry taint without explicit arguments."""

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<local-callable-state>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("body", [
    "return raw()",
    "alias = raw\n    return alias()",
    "def nested(value=raw):\n        return value\n    return nested()",
    "def nested(*, value=raw):\n        return value\n    return nested()",
])
def test_tracked_local_callable_value_keeps_input_flow(body):
    result = summaries(f"def handle(raw):\n    {body}\n")["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)
    assert any(pi == 0 and name.startswith("<shadowed:") for pi, name, _ in result.return_effects)
    assert not _param_cleanly_sanitized(result, 0, {"html.escape"})


def test_callable_value_flow_cannot_be_a_clean_sanitizer_sibling():
    result = summaries(
        "import html\ndef handle(raw):\n"
        "    alias = raw\n    return html.escape(raw) + alias()\n"
    )["handle"]
    assert result.param_taints_return(0)
    assert not _param_cleanly_sanitized(result, 0, {"html.escape"})


def test_known_module_helper_join_keeps_existing_flow():
    result = summaries(
        "def helper(value):\n    return value\n"
        "def handle(raw):\n    return helper(raw)\n"
    )["handle"]
    assert result.return_effects == frozenset({(0, "", -1)})


def test_constant_local_callable_without_input_keeps_empty_summary():
    result = summaries(
        "def handle(raw):\n    def nested():\n        return 0\n    return nested()\n"
    )["handle"]
    assert not result.summary_unknown
    assert not result.param_taints_return(0)
