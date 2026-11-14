"""None is a hashable graph node, not an internal stop marker."""

import pytest

from core.analysis.dominators import AdjacencyGraph, _UnionFind, build_dom_tree


@pytest.mark.parametrize("entry, adjacency, expected", [
    (None, {None: ["middle"], "middle": ["leaf"], "leaf": []},
     [None, "middle", "leaf"]),
    ("root", {"root": [None], None: ["leaf"], "leaf": []},
     ["root", None, "leaf"]),
])
def test_none_node_remains_in_dominator_queries(entry, adjacency, expected):
    tree = build_dom_tree(AdjacencyGraph(entry=entry, adjacency=adjacency))
    assert tree.dominators_of("leaf") == expected
    assert tree.dominates(None, "leaf")
    assert tree.dominates(None, None)
    assert tree.dominators_of(None) == expected[:expected.index(None) + 1]
    assert not tree.dominates("leaf", None)
    assert tree.dominators_of("missing") == []


def test_none_leaf_remains_reflexive():
    tree = build_dom_tree(AdjacencyGraph(entry="root", adjacency={"root": [None]}))
    assert tree.dominators_of(None) == ["root", None]
    assert tree.dominates(None, None)
    assert tree.dominates("root", None)


def test_unreachable_none_remains_absent():
    tree = build_dom_tree(AdjacencyGraph(entry="root", adjacency={"root": [], None: []}))
    assert tree.dominators_of(None) == []
    assert not tree.dominates(None, None)


def test_union_find_distinguishes_none_node_from_unlinked_root():
    semi = {"root": 0, None: 1, "leaf": 2}
    forest = _UnionFind(semi)
    for node in semi:
        forest.make(node)
    forest.link("root", None)
    forest.link(None, "leaf")
    assert forest.eval("leaf") == "root"
    assert forest.eval(None) == "root"
