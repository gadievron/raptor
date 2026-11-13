"""Type-alias creation binds a name without evaluating its lazy expressions."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.dataflow import reaching_defs

pytestmark = pytest.mark.skipif(not hasattr(ast, "TypeAlias"), reason="type statements require Python 3.12+")


def build(statement):
    source = f"def handle(raw):\n    {statement}\n    return raw\n"
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    alias = next(node for node in cfg.nodes() if node.kind == "stmt" and node.lineno == 2)
    return cfg, alias


@pytest.mark.parametrize("statement", [
    "type Alias = escape(raw)",
    "type Alias = raw.field",
    "type Alias = Later",
    "type Alias[T: bound(raw)] = wrap(T)",
    "type Alias[T = default(raw)] = wrap(T)",
    "type Alias[T: (first(raw), second(raw)) = default(raw)] = wrap(T)",
])
def test_lazy_value_and_type_parameter_calls_are_not_eager_statement_work(statement):
    _, alias = build(statement)
    assert alias.defs == frozenset({"Alias"})
    assert alias.uses == frozenset()
    assert alias.calls == frozenset()
    assert alias.call_sites == ()


def test_regular_assignment_keeps_its_eager_call_and_value_binding():
    _, assignment = build("Alias = escape(raw)")
    assert assignment.calls == frozenset({"escape"})
    assert assignment.defs == frozenset({"Alias"})
    assert "raw" in assignment.uses
    assert assignment.call_sites[0].assigned_names == frozenset({"Alias"})


def test_alias_creation_rebinds_its_name_without_rebinding_the_input():
    source = "def handle(raw):\n    Alias = escape(raw)\n    type Alias = lazy(raw)\n    consume(Alias, raw)\n"
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    nodes = {node.lineno: node for node in cfg.nodes() if node.kind == "stmt"}
    facts = reaching_defs(cfg)
    assert facts.at(nodes[4], "Alias") == frozenset({nodes[3]})
    assert facts.at(nodes[4], "raw") == frozenset({cfg.entry})
    assert not nodes[3].calls and not nodes[3].call_sites


def test_adjacent_eager_calls_keep_their_own_statement_metadata():
    source = "def handle(raw):\n    before(raw)\n    type Alias = lazy(raw)\n    after(raw)\n"
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    nodes = {node.lineno: node for node in cfg.nodes() if node.kind == "stmt"}
    assert nodes[2].calls == frozenset({"before"})
    assert not nodes[3].calls
    assert nodes[4].calls == frozenset({"after"})
