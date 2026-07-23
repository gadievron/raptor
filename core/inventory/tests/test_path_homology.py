"""Tests for path-homology Betti numbers (Phase 1).

The strongest oracle here is the *complete layered digraph*
``K_{n_1,…,n_L}`` (Huntsman 2020, eq. 8, after Chowdhury–Gebhart–
Huntsman–Yutin): ``L`` layers, layer ``ℓ`` has ``n_ℓ`` vertices, every
vertex in a layer has an edge to every vertex in the next. Its reduced
path homology is exactly

    β̃_p = δ_{p, L-1} · Π_ℓ (n_ℓ − 1)

i.e. all reduced Betti numbers vanish except in dimension ``L−1``, where
it equals the product of ``(n_ℓ − 1)``. This gives a closed-form Betti
number in *every* dimension from a trivially-constructed graph, so it
pins the higher-dimensional machinery (β_2, β_3) that is the whole point
of path homology — far more robustly than reverse-engineering figures.
"""

import sys
from pathlib import Path

# core/inventory/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.inventory.path_homology import (  # noqa: E402
    BettiVector,
    betti,
    betti_from_adjacency,
    cyclomatic_number,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

def _layered(layer_sizes):
    """Build the complete layered digraph K_{n_1,…,n_L} as an adjacency
    map. Vertices are integers numbered layer by layer; every vertex in
    layer ℓ points to every vertex in layer ℓ+1."""
    layers = []
    nxt = 0
    for size in layer_sizes:
        layers.append(list(range(nxt, nxt + size)))
        nxt += size
    adj = {v: [] for v in range(nxt)}
    for a, b in zip(layers, layers[1:]):
        for u in a:
            adj[u] = list(b)
    return adj


def _expected_reduced(layer_sizes):
    """β̃_p = δ_{p,L-1} · Π(n_ℓ − 1)."""
    L = len(layer_sizes)
    prod = 1
    for n in layer_sizes:
        prod *= (n - 1)
    return {L - 1: prod}


def _directed_cycle(n):
    return {i: [(i + 1) % n] for i in range(n)}


# ---------------------------------------------------------------------------
# Degenerate / base cases
# ---------------------------------------------------------------------------

class TestBaseCases:
    def test_empty_graph(self):
        r = betti_from_adjacency({}, max_dim=3)
        assert r.betti == (0, 0, 0, 0)
        assert r.complete is True

    def test_single_vertex(self):
        r = betti_from_adjacency({0: []}, max_dim=3)
        assert r.b0 == 1
        assert r.b1 == 0 and r.b2 == 0

    def test_single_edge_is_contractible(self):
        r = betti_from_adjacency({0: [1], 1: []}, max_dim=3)
        assert r.b0 == 1
        assert r.b1 == 0

    def test_self_loop_dropped(self):
        # Loopless theory: a self-loop must be ignored, not crash.
        r = betti_from_adjacency({0: [0]}, max_dim=2)
        assert r.b0 == 1
        assert r.b1 == 0


# ---------------------------------------------------------------------------
# β_0 = weakly-connected components
# ---------------------------------------------------------------------------

class TestBetti0:
    def test_two_isolated_vertices(self):
        assert betti_from_adjacency({0: [], 1: []}, max_dim=1).b0 == 2

    def test_three_components(self):
        adj = {0: [1], 1: [], 2: [3], 3: [], 4: []}
        assert betti_from_adjacency(adj, max_dim=1).b0 == 3

    def test_weak_connectivity_ignores_direction(self):
        # 0->1, 2->1 : weakly connected despite no directed path between
        # the two sources.
        assert betti_from_adjacency({0: [1], 2: [1]}, max_dim=1).b0 == 1


# ---------------------------------------------------------------------------
# β_1 on directed cycles
# ---------------------------------------------------------------------------

class TestDirectedCycles:
    def test_two_cycle(self):
        # Non-regular path homology of a directed 2-cycle: one cycle, no
        # higher homology (β=(1,1,0)).
        r = betti_from_adjacency(_directed_cycle(2), max_dim=2)
        assert r.betti == (1, 1, 0)

    def test_three_cycle(self):
        r = betti_from_adjacency(_directed_cycle(3), max_dim=2)
        assert r.betti == (1, 1, 0)

    def test_five_cycle(self):
        r = betti_from_adjacency(_directed_cycle(5), max_dim=3)
        assert r.b0 == 1 and r.b1 == 1
        assert r.b2 == 0 and r.betti[3] == 0


# ---------------------------------------------------------------------------
# Complete layered digraphs — the closed-form higher-dimensional oracle
# ---------------------------------------------------------------------------

class TestLayeredDigraphs:
    def _check(self, layer_sizes, max_dim):
        r = betti_from_adjacency(_layered(layer_sizes), max_dim=max_dim)
        assert r.complete is True
        exp_reduced = _expected_reduced(layer_sizes)
        for p in range(max_dim + 1):
            got = r.betti[p]
            want_reduced = exp_reduced.get(p, 0)
            want = want_reduced + (1 if p == 0 else 0)  # β_0 = β̃_0 + 1
            assert got == want, (
                f"K_{layer_sizes} dim {p}: got β_{p}={got}, want {want}")

    def test_k22_has_b1_one(self):
        # Complete bipartite directed: β̃_1 = (2-1)(2-1) = 1.
        self._check([2, 2], max_dim=3)

    def test_k222_has_b2_one(self):
        # Three layers ⇒ nontrivial homology in dimension 2: β_2 = 1.
        # This is the key higher-dimensional case.
        self._check([2, 2, 2], max_dim=3)

    def test_k2222_has_b3_one(self):
        self._check([2, 2, 2, 2], max_dim=3)

    def test_k32_has_b1_two(self):
        # β̃_1 = (3-1)(2-1) = 2.
        self._check([3, 2], max_dim=2)

    def test_k322_has_b2_two(self):
        # β̃_2 = (3-1)(2-1)(2-1) = 2.
        self._check([3, 2, 2], max_dim=3)


# ---------------------------------------------------------------------------
# Structured (reducible) control flow: β_{≥2} = 0, β_1 = cyclomatic
# ---------------------------------------------------------------------------

class TestStructuredControlFlow:
    def _if_then_else(self):
        # entry -> {then, else} -> join
        return {0: [1, 2], 1: [3], 2: [3], 3: []}

    def _while_loop(self):
        # entry -> head; head -> {body, exit}; body -> head
        return {0: [1], 1: [2, 3], 2: [1], 3: []}

    def test_if_then_else_trivial_higher(self):
        r = betti_from_adjacency(self._if_then_else(), max_dim=3)
        # A "diamond" is path-contractible: β = (1,0,0,0).
        assert r.betti == (1, 0, 0, 0)

    def test_while_loop_one_cycle_no_higher(self):
        r = betti_from_adjacency(self._while_loop(), max_dim=3)
        assert r.b0 == 1 and r.b1 == 1
        assert r.b2 == 0 and r.betti[3] == 0

    def test_betti1_matches_cyclomatic_on_loops(self):
        # On genuine loops (back edges / directed cycles) path-β_1 agrees
        # with directed cyclomatic complexity.
        for adj in (self._while_loop(), _directed_cycle(4),
                    _directed_cycle(2)):
            g = _Adj(adj)
            assert betti(g).b1 == cyclomatic_number(g)

    def test_diamond_diverges_from_cyclomatic(self):
        # The direction-aware divergence: an if/else diamond has
        # cyclomatic 1 but path-β_1 = 0 — path homology fills the
        # commutative square between the two branches.
        g = _Adj(self._if_then_else())
        assert cyclomatic_number(g) == 1
        assert betti(g).b1 == 0


# ---------------------------------------------------------------------------
# cyclomatic_number helper
# ---------------------------------------------------------------------------

class _Adj:
    """Minimal Graph-protocol object over an adjacency dict."""

    def __init__(self, adj):
        self._adj = adj
        self._nodes = list(adj.keys())

    @property
    def entry(self):
        return self._nodes[0]

    def nodes(self):
        return list(self._nodes)

    def successors(self, n):
        return self._adj.get(n, [])


class TestCyclomatic:
    def test_tree_is_zero(self):
        assert cyclomatic_number(_Adj({0: [1, 2], 1: [], 2: []})) == 0

    def test_single_cycle_is_one(self):
        assert cyclomatic_number(_Adj(_directed_cycle(4))) == 1

    def test_two_cycle_counts_both_directed_edges(self):
        # a<->b: two directed edges, two vertices, one component:
        # 2 - 2 + 1 = 1 (matches path-β_1 of the directed 2-cycle).
        assert cyclomatic_number(_Adj(_directed_cycle(2))) == 1

    def test_graph_protocol_input_matches_adjacency(self):
        adj = {0: [1], 1: [2, 3], 2: [1], 3: []}
        assert betti(_Adj(adj)).betti == betti_from_adjacency(adj).betti


# ---------------------------------------------------------------------------
# Budget / incompleteness + BettiVector surface
# ---------------------------------------------------------------------------

class TestBudgetAndVector:
    def test_truncation_marks_incomplete(self):
        # A dense graph with a tiny budget must truncate and say so.
        adj = {i: [j for j in range(6) if j != i] for i in range(6)}
        r = betti_from_adjacency(adj, max_dim=3, max_paths_per_dim=5)
        assert r.complete is False
        # Whatever prefix it returns must be a correct prefix length.
        assert len(r.betti) <= 4

    def test_reduced_subtracts_one_from_b0(self):
        r = betti_from_adjacency(_layered([2, 2, 2]), max_dim=3)
        assert r.reduced() == (0,) + tuple(r.betti[1:])

    def test_str_is_readable(self):
        r = BettiVector(betti=(1, 2, 0), max_dim=2, complete=True)
        assert "β = (1, 2, 0)" in str(r)
        assert "truncated" in str(
            BettiVector(betti=(1,), max_dim=3, complete=False))

    def test_max_dim_zero_gives_just_b0(self):
        r = betti_from_adjacency(_directed_cycle(3), max_dim=0)
        assert r.betti == (1,)
