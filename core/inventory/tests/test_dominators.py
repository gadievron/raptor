"""Tests for ``core.inventory.dominators`` — Phase 5a.

The fixture graphs cover the key dominator-tree shapes plus a few
adversarial / pathological cases:

* Linear chain — each node's idom is its predecessor.
* Diamond — A dominates the join node.
* Loop with back-edge — the loop header dominates the body.
* Nested loops — the outer header dominates the inner.
* Multiple entry-paths merging — checks LCA-style idom computation.
* Self-loop.
* Unreachable nodes — silently pruned.
* Disconnected reachability.
* Lengauer–Tarjan §3 example graph (the textbook case).

A NetworkX cross-check runs when ``networkx`` is importable —
test-only soft dep; skipped silently when absent (project keeps
``networkx`` out of runtime deps).
"""
from __future__ import annotations

import pytest

from core.inventory.dominators import (
    AdjacencyGraph,
    DomTree,
    build_dom_tree,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _graph(entry: str, edges: dict) -> AdjacencyGraph:
    return AdjacencyGraph(entry=entry, adjacency=edges)


def _idom_map(tree: DomTree) -> dict:
    """``{node: idom}`` for every reachable node. Entry maps to ``None``
    by the ``idom`` API convention (no proper immediate dominator)."""
    return {n: tree.idom(n) for n in tree.nodes()}


# ---------------------------------------------------------------------------
# Linear / diamond / trivial
# ---------------------------------------------------------------------------


def test_single_node():
    g = _graph("A", {"A": []})
    t = build_dom_tree(g)
    assert t.idom("A") is None
    assert t.dominates("A", "A")
    assert t.dominators_of("A") == ["A"]


def test_linear_chain():
    g = _graph("A", {"A": ["B"], "B": ["C"], "C": ["D"]})
    t = build_dom_tree(g)
    assert _idom_map(t) == {"A": None, "B": "A", "C": "B", "D": "C"}
    # dominators_of returns the full prefix path
    assert t.dominators_of("D") == ["A", "B", "C", "D"]


def test_diamond():
    """A → {B, C} → D. A dominates everything; D's idom is A
    because B and C are both on disjoint paths to D — neither
    dominates D."""
    g = _graph("A", {"A": ["B", "C"], "B": ["D"], "C": ["D"]})
    t = build_dom_tree(g)
    assert _idom_map(t) == {"A": None, "B": "A", "C": "A", "D": "A"}
    assert t.dominates("A", "D")
    assert not t.dominates("B", "D")
    assert not t.dominates("C", "D")


# ---------------------------------------------------------------------------
# Loops
# ---------------------------------------------------------------------------


def test_self_loop():
    """A → B; B → B. B's idom is A; A dominates both."""
    g = _graph("A", {"A": ["B"], "B": ["B"]})
    t = build_dom_tree(g)
    assert t.idom("A") is None
    assert t.idom("B") == "A"


def test_simple_loop_with_back_edge():
    """A → B → C → B (back-edge). A dominates everything;
    B dominates C (every path from entry to C passes through B)."""
    g = _graph("A", {"A": ["B"], "B": ["C"], "C": ["B"]})
    t = build_dom_tree(g)
    assert _idom_map(t) == {"A": None, "B": "A", "C": "B"}
    assert t.dominates("B", "C")


def test_nested_loops():
    """A → B → C → D → C (inner back-edge) → E → B (outer back-edge).
    Loop headers dominate their bodies."""
    g = _graph("A", {
        "A": ["B"], "B": ["C"], "C": ["D"], "D": ["C", "E"], "E": ["B"],
    })
    t = build_dom_tree(g)
    assert t.dominates("B", "C")
    assert t.dominates("B", "D")
    assert t.dominates("C", "D")
    assert t.dominates("B", "E")


# ---------------------------------------------------------------------------
# Multiple-path merge
# ---------------------------------------------------------------------------


def test_three_way_merge():
    """A → {B, C, D} → E. E's idom is A; none of B/C/D dominate E."""
    g = _graph("A", {
        "A": ["B", "C", "D"],
        "B": ["E"], "C": ["E"], "D": ["E"],
    })
    t = build_dom_tree(g)
    assert _idom_map(t) == {
        "A": None, "B": "A", "C": "A", "D": "A", "E": "A",
    }


def test_uneven_join():
    """A → B → C; A → C. C's idom is A (because the direct edge
    A → C means B isn't on every path)."""
    g = _graph("A", {"A": ["B", "C"], "B": ["C"]})
    t = build_dom_tree(g)
    assert t.idom("C") == "A"
    assert not t.dominates("B", "C")


# ---------------------------------------------------------------------------
# Lengauer–Tarjan textbook example
# ---------------------------------------------------------------------------


def test_lengauer_tarjan_paper_example():
    """The 13-node flow graph from Lengauer & Tarjan, 1979, Fig. 1.

    Known immediate dominators (paper notation, R is entry):
        R: -, A: R, B: R, C: R, D: R, E: R, F: C, G: C,
        H: C, I: R, J: G, K: R, L: D.
    Edges (from the paper):
        R → A, R → B, R → C
        A → D, B → A, B → D, B → E
        C → F, C → G, D → L, E → H, F → I,
        G → I, G → J, H → E, H → K, I → K,
        J → I, K → I, K → R, L → H
    """
    edges = {
        "R": ["A", "B", "C"],
        "A": ["D"],
        "B": ["A", "D", "E"],
        "C": ["F", "G"],
        "D": ["L"],
        "E": ["H"],
        "F": ["I"],
        "G": ["I", "J"],
        "H": ["E", "K"],
        "I": ["K"],
        "J": ["I"],
        "K": ["I", "R"],
        "L": ["H"],
    }
    g = _graph("R", edges)
    t = build_dom_tree(g)
    expected = {
        "R": None,
        "A": "R", "B": "R", "C": "R", "D": "R", "E": "R",
        "F": "C", "G": "C", "H": "R", "I": "R",
        "J": "G", "K": "R", "L": "D",
    }
    assert _idom_map(t) == expected


# ---------------------------------------------------------------------------
# Unreachable / disconnected
# ---------------------------------------------------------------------------


def test_unreachable_nodes_pruned():
    """Nodes with no path from entry are dropped silently from the
    tree."""
    g = _graph("A", {"A": ["B"], "B": [], "X": ["Y"], "Y": []})
    t = build_dom_tree(g)
    reachable = set(t.nodes())
    assert reachable == {"A", "B"}
    # Queries on pruned nodes return None / False / [].
    assert t.idom("X") is None
    assert not t.dominates("X", "A")
    assert t.dominators_of("X") == []


def test_disconnected_reachable_subgraph():
    """When only some nodes are reachable, the dom tree describes
    exactly the reachable subgraph."""
    g = _graph("A", {
        "A": ["B"], "B": ["C"],
        "X": ["A"],  # X points INTO the reachable component but
                     # isn't reachable FROM A itself.
    })
    t = build_dom_tree(g)
    assert set(t.nodes()) == {"A", "B", "C"}


# ---------------------------------------------------------------------------
# dominates() invariants
# ---------------------------------------------------------------------------


class TestDominatesInvariants:
    def test_reflexive(self):
        g = _graph("A", {"A": ["B"], "B": []})
        t = build_dom_tree(g)
        for n in t.nodes():
            assert t.dominates(n, n), f"{n} should dominate itself"

    def test_transitive(self):
        """If a dominates b and b dominates c, then a dominates c."""
        g = _graph("A", {"A": ["B"], "B": ["C"], "C": ["D"]})
        t = build_dom_tree(g)
        # A dominates B, B dominates C → A dominates C.
        assert t.dominates("A", "B")
        assert t.dominates("B", "C")
        assert t.dominates("A", "C")

    def test_unreachable_dominates_nothing(self):
        g = _graph("A", {"A": []})
        t = build_dom_tree(g)
        assert not t.dominates("X", "A")
        assert not t.dominates("A", "X")


# ---------------------------------------------------------------------------
# AdjacencyGraph helper
# ---------------------------------------------------------------------------


def test_adjacency_graph_emits_all_nodes_including_leaves():
    """Leaf nodes (no outgoing edges) are inferred from the adjacency
    map's value lists even when they have no key."""
    g = AdjacencyGraph(entry="A", adjacency={"A": ["B", "C"]})
    assert set(g.nodes()) == {"A", "B", "C"}
    assert list(g.successors("A")) == ["B", "C"]
    assert list(g.successors("B")) == []


def test_adjacency_graph_no_duplicates():
    g = AdjacencyGraph(entry="A", adjacency={"A": ["B", "B", "C"]})
    seen = list(g.nodes())
    assert len(seen) == len(set(seen))


# ---------------------------------------------------------------------------
# NetworkX cross-check (optional)
# ---------------------------------------------------------------------------


def _maybe_networkx():
    try:
        import networkx
        return networkx
    except ImportError:
        return None


@pytest.mark.skipif(_maybe_networkx() is None,
                    reason="networkx not installed (test-only optional dep)")
def test_matches_networkx_on_random_dag():
    """Cross-check our dominator output against NetworkX's
    ``immediate_dominators`` on a moderately-sized random DAG.
    Ensures we don't have a subtle off-by-one or label-swap bug."""
    import random
    import networkx as nx

    random.seed(0xC0FFEE)
    n = 30
    edges = {f"v{i}": [] for i in range(n)}
    edges["v0"] = []  # entry
    # Random DAG: each node points to a few later nodes
    for i in range(n):
        n_succ = random.randint(0, 3)
        for _ in range(n_succ):
            j = random.randint(i + 1, n - 1) if i + 1 < n else None
            if j is not None and f"v{j}" not in edges[f"v{i}"]:
                edges[f"v{i}"].append(f"v{j}")
    # NetworkX reference
    nxg = nx.DiGraph()
    for u, vs in edges.items():
        for v in vs:
            nxg.add_edge(u, v)
    if "v0" not in nxg.nodes:
        nxg.add_node("v0")
    nx_idom = nx.immediate_dominators(nxg, "v0")
    # Our tree
    g = _graph("v0", edges)
    t = build_dom_tree(g)
    # NX reports idom[entry] == entry; we report None. Bridge the
    # convention for comparison.
    for node, expected_idom in nx_idom.items():
        if node == "v0":
            continue
        ours = t.idom(node)
        assert ours == expected_idom, (
            f"{node}: ours={ours} nx={expected_idom}"
        )
