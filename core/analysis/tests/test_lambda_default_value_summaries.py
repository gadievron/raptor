"""Lambda defaults are evaluated values retained by the callable object."""

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summary(body, *, prefix=""):
    source = prefix + "def handle(raw):\n" + "".join(f"    {line}\n" for line in body.splitlines())
    compile(source, "<lambda-default-value>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)["handle"]


@pytest.mark.parametrize("expression", ["lambda value=raw: value", "lambda *, value=raw: value"])
def test_assigned_lambda_default_keeps_input_flow_on_call(expression):
    result = summary(f"thunk = {expression}\nreturn thunk()")
    assert result.param_taints_return(0)
    assert not _param_cleanly_sanitized(result, 0, {"html.escape"})


def test_lambda_default_is_a_snapshot_not_the_later_local_rebind():
    result = summary("tmp = raw\nthunk = lambda value=tmp: value\ntmp = 0\nreturn thunk()")
    assert result.param_taints_return(0)


def test_default_effect_context_cannot_restore_a_shadowed_catalog_name():
    result = summary("html = raw\nthunk = lambda value=html.escape(raw): value\nreturn thunk()")
    assert result.param_taints_return(0)
    assert not _param_cleanly_sanitized(result, 0, {"html.escape"})
    assert any(name.startswith("<shadowed:") for _, name, _ in result.return_effects)


def test_default_callable_taint_survives_next_to_a_catalog_effect():
    result = summary("thunk = lambda value=raw: value\nreturn html.escape(raw) + thunk()", prefix="import html\n")
    assert not _param_cleanly_sanitized(result, 0, {"html.escape"})


def test_constant_default_without_input_keeps_empty_summary():
    result = summary("thunk = lambda value=0: value\nreturn thunk()")
    assert not result.summary_unknown
    assert not result.param_taints_return(0)


def test_returned_callable_object_cannot_inherit_default_sanitizer_authority():
    result = summary("return lambda value=html.escape(raw): value", prefix="import html\n")
    assert result.param_taints_return(0)
    assert not _param_cleanly_sanitized(result, 0, {"html.escape"})
