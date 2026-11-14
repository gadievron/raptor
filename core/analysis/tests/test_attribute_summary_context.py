"""Attribute projections preserve the call identity context of their base."""

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summary(prefix, signature, body, expression):
    source = f"{prefix}def handle({signature}):\n{body}    return {expression}\n"
    compile(source, "<attribute-summary-context>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)["handle"]


@pytest.mark.parametrize("prefix,signature,body", [
    ("", "raw, html", ""),
    ("", "raw, fake", "    html = fake\n"),
    ("import fakelib as html\n", "raw", ""),
])
@pytest.mark.parametrize("suffix", [".field", ".field.nested"])
def test_attribute_result_keeps_local_shadow_and_module_distrust(prefix, signature, body, suffix):
    direct = summary(prefix, signature, body, "html.escape(raw)")
    projected = summary(prefix, signature, body, f"html.escape(raw){suffix}")
    assert projected.return_effects == direct.return_effects
    assert projected.param_taints_return(0)
    assert not _param_cleanly_sanitized(projected, 0, {"html.escape"})


def test_unshadowed_catalog_effect_keeps_existing_structural_result():
    direct = summary("import html\n", "raw", "", "html.escape(raw)")
    projected = summary("import html\n", "raw", "", "html.escape(raw).field")
    assert projected.return_effects == direct.return_effects
    assert projected.return_sanitizers_for_param(0) == frozenset({("html.escape", 0)})
    # This is a structural candidate query, not source-contract admission.
    assert _param_cleanly_sanitized(projected, 0, {"html.escape"})
