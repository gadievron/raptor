"""Graph identifiers are equal by value, without object identity requirements."""

from dataclasses import dataclass

from core.analysis.dataflow import reaching_defs


@dataclass(frozen=True)
class Node:
    name: str
    defs: frozenset[str] = frozenset()


class ValueGraph:
    params = ("Value",)

    def __init__(self, edges, definitions=None):
        self.edges = edges
        self.definitions = definitions or {}

    def node(self, name):
        return Node(name, frozenset(self.definitions.get(name, ())))

    @property
    def entry(self):
        return self.node("entry")

    def nodes(self):
        return tuple(self.node(name) for name in self.edges)

    def successors(self, node):
        return tuple(self.node(name) for name in self.edges[node.name])


def test_equal_distinct_entry_identifiers_still_define_parameters():
    graph = ValueGraph({"entry": ("use",), "use": ()}, {"entry": ("Flag",)})
    listed_entry = graph.nodes()[0]
    assert listed_entry == graph.entry and listed_entry is not graph.entry
    result = reaching_defs(graph)
    assert result.at(graph.node("use"), "Value") == frozenset({graph.entry})
    assert result.at(graph.node("use"), "Flag") == frozenset({graph.entry})


def test_equal_entry_parameter_is_killed_by_a_later_redefinition():
    graph = ValueGraph({"entry": ("rewrite",), "rewrite": ("use",), "use": ()},
                       {"rewrite": ("Value",)})
    result = reaching_defs(graph)
    assert result.at(graph.node("rewrite"), "Value") == frozenset({graph.entry})
    assert result.at(graph.node("use"), "Value") == frozenset({graph.node("rewrite")})


def test_branch_merge_keeps_entry_and_branch_parameter_definitions():
    graph = ValueGraph({"entry": ("rewrite", "use"), "rewrite": ("use",), "use": ()},
                       {"rewrite": ("Value",)})
    result = reaching_defs(graph)
    assert result.at(graph.node("use"), "Value") == frozenset({graph.entry, graph.node("rewrite")})


def test_loop_keeps_initial_and_loop_carried_definitions_with_fresh_identifiers():
    graph = ValueGraph({"entry": ("head",), "head": ("rewrite", "use"),
                        "rewrite": ("head",), "use": ()}, {"rewrite": ("Value",)})
    result = reaching_defs(graph)
    assert result.at(graph.node("use"), "Value") == frozenset({graph.entry, graph.node("rewrite")})


def test_a_graph_without_parameters_keeps_only_its_explicit_entry_definition():
    graph = ValueGraph({"entry": ("use",), "use": ()}, {"entry": ("Flag",)})
    graph.params = ()
    result = reaching_defs(graph)
    assert result.at(graph.node("use"), "Value") == frozenset()
    assert result.at(graph.node("use"), "Flag") == frozenset({graph.entry})
