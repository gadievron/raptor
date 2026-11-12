"""Lambda defaults execute in the enclosing scope when the lambda is created."""

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.dataflow import reaching_defs
from core.analysis.sanitizer_cut import evaluate_finding


def build(default):
    source = (
        "import html\n"
        "def handle(raw):\n"
        "    tmp = html.escape(raw)\n"
        f"    thunk = {default}\n"
        "    render(tmp)\n"
    )
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    nodes = {node.lineno: node for node in cfg.nodes() if node.kind == "stmt"}
    return cfg, nodes


def test_eager_lambda_default_rebinding_replaces_the_prior_definition():
    cfg, nodes = build("lambda value=(tmp := raw): None")
    assert "tmp" in nodes[4].defs and "raw" in nodes[4].uses
    assert reaching_defs(cfg).at(nodes[5], "tmp") == frozenset({nodes[4]})


def test_lambda_default_rebinding_cannot_keep_the_sanitizer_value_binding():
    cfg, nodes = build("lambda value=(tmp := raw): None")
    result = evaluate_finding(cfg, [cfg.entry], nodes[5], cwe="CWE-79", language="python",
                              source_symbols={"raw"}, sink_arg="tmp")
    assert result.all_matched_bindings
    assert not result.value_bound_bindings
    assert result.suppress is False


@pytest.mark.parametrize("default", [
    "lambda *, value=(tmp := raw): None",
    "lambda tmp=(tmp := raw): None",
    "lambda value=(lambda nested=(tmp := raw): None): None",
], ids=["keyword-only", "same-name-parameter", "nested-eager-default"])
def test_other_eager_default_forms_rebind_only_the_enclosing_value(default):
    cfg, nodes = build(default)
    assert nodes[4].defs == frozenset({"thunk", "tmp"})
    assert "raw" in nodes[4].uses
    assert reaching_defs(cfg).at(nodes[5], "tmp") == frozenset({nodes[4]})


@pytest.mark.parametrize("default,loaded", [
    ("lambda raw=raw: None", "raw"),
    ("lambda raw=tmp: None", "tmp"),
    ("lambda *, raw=tmp: None", "tmp"),
], ids=["same-parameter-load", "outer-local", "keyword-local"])
def test_default_loads_precede_lambda_parameter_scope(default, loaded):
    cfg, nodes = build(default)
    assert nodes[4].defs == frozenset({"thunk"})
    assert loaded in nodes[4].uses
    assert reaching_defs(cfg).at(nodes[5], "tmp") == frozenset({nodes[3]})


def test_default_without_rebinding_retains_the_conditional_value_binding():
    cfg, nodes = build("lambda value=raw: None")
    result = evaluate_finding(cfg, [cfg.entry], nodes[5], cwe="CWE-79", language="python",
                              source_symbols={"raw"}, sink_arg="tmp")
    assert result.value_bound_bindings
    assert result.suppress is False
    assert all(binding.unverified_source_contracts for binding in result.value_bound_bindings)


def test_deferred_lambda_body_call_is_not_an_eager_sanitizer():
    cfg, nodes = build("lambda value: html.escape(raw)")
    assert not nodes[4].calls and not nodes[4].call_sites
    assert reaching_defs(cfg).at(nodes[5], "tmp") == frozenset({nodes[3]})
