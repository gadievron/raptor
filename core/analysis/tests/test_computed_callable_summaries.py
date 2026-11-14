"""Computed callable values retain taint independently of call arguments."""

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summary(expression, *, prefix=""):
    source = prefix + f"def handle(raw, flag):\n    return {expression}\n"
    compile(source, "<computed-callable-summary>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)["handle"]


@pytest.mark.parametrize("expression,prefix", [
    ("raw[0]()", ""),
    ("[raw][0]()", ""),
    ("(raw if flag else fallback)()", ""),
    ("identity(raw)()", "def identity(value):\n    return value\n"),
])
def test_computed_callable_input_keeps_opaque_flow(expression, prefix):
    result = summary(expression, prefix=prefix)
    assert result.param_taints_return(0)
    assert any(pi == 0 and name == "<callable>" for pi, name, _ in result.return_effects)
    assert not _param_cleanly_sanitized(result, 0, {"html.escape"})


def test_computed_callable_cannot_be_clean_sanitizer_sibling():
    result = summary("html.escape(raw) + raw[0]()", prefix="import html\n")
    assert not _param_cleanly_sanitized(result, 0, {"html.escape"})


def test_method_and_inline_lambda_keep_their_existing_receiver_markers():
    for expression in ["raw.strip()", "(lambda: raw)()"]:
        result = summary(expression)
        assert result.param_taints_return(0)
        assert all(name != "<callable>" for _, name, _ in result.return_effects)


def test_known_module_helper_join_keeps_direct_flow():
    result = summary("identity(raw)", prefix="def identity(value):\n    return value\n")
    assert result.return_effects == frozenset({(0, "", -1)})
