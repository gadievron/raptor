"""Assignment expressions inside lambda bodies bind the lambda's own frame."""

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.dataflow import reaching_defs


def graph(expression):
    source = (
        "def handle(raw, rows):\n"
        "    tmp = raw\n"
        f"    thunk = {expression}\n"
        "    consume(tmp)\n"
    )
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    nodes = {node.lineno: node for node in cfg.nodes() if node.kind == "stmt"}
    return cfg, nodes


def test_deferred_lambda_walrus_does_not_redefine_the_outer_local():
    cfg, nodes = graph("lambda value: (tmp := value)")
    assert nodes[3].defs == frozenset({"thunk"})
    assert reaching_defs(cfg).at(nodes[4], "tmp") == frozenset({nodes[2]})


@pytest.mark.parametrize("expression,free_names", [
    ("lambda: ((tmp := raw), tmp)", {"raw"}),
    ("lambda: (tmp + (tmp := raw))", {"raw"}),
    ("lambda: [(tmp := value) for value in rows]", {"rows"}),
    ("lambda: ((tmp := value) for value in rows)", {"rows"}),
    ("lambda: (lambda value=(tmp := raw): None)", {"raw"}),
    ("lambda: (tmp, lambda value: (tmp := value))", {"tmp"}),
], ids=["local-read", "read-before-binding", "list-comprehension", "generator",
        "nested-default-local", "nested-body-separate"])
def test_lambda_binding_scope_does_not_leak_into_the_enclosing_graph(expression, free_names):
    cfg, nodes = graph(expression)
    assert nodes[3].defs == frozenset({"thunk"})
    assert nodes[3].uses == frozenset(free_names)
    assert reaching_defs(cfg).at(nodes[4], "tmp") == frozenset({nodes[2]})


def test_outer_default_rebinding_is_not_hidden_by_a_lambda_local_of_the_same_name():
    cfg, nodes = graph("lambda value=(tmp := raw): (tmp := value)")
    assert nodes[3].defs == frozenset({"thunk", "tmp"})
    assert nodes[3].uses == frozenset({"raw"})
    assert reaching_defs(cfg).at(nodes[4], "tmp") == frozenset({nodes[3]})


def test_outer_default_read_survives_a_same_named_local_in_the_body():
    cfg, nodes = graph("lambda value=tmp: (tmp := value)")
    assert nodes[3].defs == frozenset({"thunk"})
    assert nodes[3].uses == frozenset({"tmp"})
    assert reaching_defs(cfg).at(nodes[4], "tmp") == frozenset({nodes[2]})
