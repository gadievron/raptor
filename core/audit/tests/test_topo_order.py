"""Tests for core.audit.topo_order — topological ordering + SCC detection."""

from core.audit.topo_order import (
    SCC,
    build_adjacency_from_gaps,
    detect_sccs,
    merge_with_priority,
    resolve_scc_summaries,
    topological_sort,
)


class TestDetectSCCs:
    def test_empty_graph(self):
        assert detect_sccs({}) == []

    def test_single_node_no_edges(self):
        sccs = detect_sccs({"a": []})
        assert len(sccs) == 1
        assert sccs[0].members == frozenset({"a"})
        assert not sccs[0].is_cycle

    def test_linear_chain(self):
        adj = {"a": ["b"], "b": ["c"], "c": []}
        sccs = detect_sccs(adj)
        assert len(sccs) == 3
        for scc in sccs:
            assert len(scc) == 1
            assert not scc.is_cycle

    def test_simple_cycle(self):
        adj = {"a": ["b"], "b": ["a"]}
        sccs = detect_sccs(adj)
        assert len(sccs) == 1
        assert sccs[0].members == frozenset({"a", "b"})
        assert sccs[0].is_cycle

    def test_diamond(self):
        adj = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
        sccs = detect_sccs(adj)
        assert len(sccs) == 4
        for scc in sccs:
            assert not scc.is_cycle

    def test_cycle_plus_tail(self):
        adj = {"a": ["b"], "b": ["c"], "c": ["b"]}
        sccs = detect_sccs(adj)
        cycle_sccs = [s for s in sccs if s.is_cycle]
        assert len(cycle_sccs) == 1
        assert cycle_sccs[0].members == frozenset({"b", "c"})

    def test_implicit_leaf_nodes(self):
        adj = {"a": ["b"]}
        sccs = detect_sccs(adj)
        assert len(sccs) == 2
        members = {frozenset(s.members) for s in sccs}
        assert frozenset({"a"}) in members
        assert frozenset({"b"}) in members

    def test_three_node_cycle(self):
        adj = {"a": ["b"], "b": ["c"], "c": ["a"]}
        sccs = detect_sccs(adj)
        assert len(sccs) == 1
        assert sccs[0].members == frozenset({"a", "b", "c"})
        assert sccs[0].is_cycle

    def test_two_separate_cycles(self):
        adj = {"a": ["b"], "b": ["a"], "c": ["d"], "d": ["c"]}
        sccs = detect_sccs(adj)
        cycle_sccs = [s for s in sccs if s.is_cycle]
        assert len(cycle_sccs) == 2


class TestTopologicalSort:
    def test_empty(self):
        assert topological_sort({}) == []

    def test_linear_chain_leaves_first(self):
        adj = {"a": ["b"], "b": ["c"], "c": []}
        order = topological_sort(adj)
        assert order.index("c") < order.index("b")
        assert order.index("b") < order.index("a")

    def test_diamond_leaves_first(self):
        adj = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
        order = topological_sort(adj)
        assert order.index("d") < order.index("b")
        assert order.index("d") < order.index("c")
        assert order.index("b") < order.index("a")
        assert order.index("c") < order.index("a")

    def test_priority_scores_break_ties(self):
        adj = {"a": ["c"], "b": ["c"], "c": []}
        scores = {"a": 10, "b": 20}
        order = topological_sort(adj, priority_scores=scores)
        assert order[0] == "c"
        a_idx = order.index("a")
        b_idx = order.index("b")
        assert b_idx < a_idx

    def test_cycle_members_ordered_by_score(self):
        adj = {"a": ["b"], "b": ["a"]}
        scores = {"a": 5, "b": 15}
        order = topological_sort(adj, priority_scores=scores)
        assert order[0] == "b"
        assert order[1] == "a"

    def test_cycle_before_caller(self):
        adj = {"root": ["a"], "a": ["b"], "b": ["a"]}
        order = topological_sort(adj)
        assert order.index("a") < order.index("root")
        assert order.index("b") < order.index("root")


class TestBuildAdjacencyFromGaps:
    def test_empty(self):
        assert build_adjacency_from_gaps([]) == {}

    def test_no_callees(self):
        gaps = [{"file": "a.c", "name": "foo"}]
        adj = build_adjacency_from_gaps(gaps)
        assert adj == {"a.c:foo": []}

    def test_with_callees(self):
        gaps = [
            {
                "file": "a.c",
                "name": "foo",
                "callees": [
                    {"file": "b.c", "name": "bar"},
                    {"file": "c.c", "name": "baz"},
                ],
            },
        ]
        adj = build_adjacency_from_gaps(gaps)
        assert set(adj["a.c:foo"]) == {"b.c:bar", "c.c:baz"}

    def test_skips_empty_callee_names(self):
        gaps = [
            {
                "file": "a.c",
                "name": "foo",
                "callees": [{"file": "", "name": "bar"}, {"file": "b.c", "name": ""}],
            },
        ]
        adj = build_adjacency_from_gaps(gaps)
        assert adj["a.c:foo"] == []


class TestMergeWithPriority:
    def test_reorders_gaps(self):
        gaps = [
            {"file": "a.c", "name": "caller", "callees": [{"file": "b.c", "name": "leaf"}]},
            {"file": "b.c", "name": "leaf"},
        ]
        adj = build_adjacency_from_gaps(gaps)
        result = merge_with_priority(adj, gaps)
        names = [g["name"] for g in result]
        assert names.index("leaf") < names.index("caller")

    def test_preserves_all_gaps(self):
        gaps = [
            {"file": "a.c", "name": "foo"},
            {"file": "b.c", "name": "bar"},
        ]
        adj = {"a.c:foo": ["b.c:bar"]}
        result = merge_with_priority(adj, gaps)
        assert len(result) == 2

    def test_gaps_not_in_adj_appended(self):
        gaps = [
            {"file": "a.c", "name": "foo"},
            {"file": "x.c", "name": "orphan"},
        ]
        adj = {"a.c:foo": []}
        result = merge_with_priority(adj, gaps)
        assert len(result) == 2
        assert result[-1]["name"] == "orphan"

    def test_priority_scores_affect_order(self):
        gaps = [
            {"file": "a.c", "name": "lo", "callees": [{"file": "c.c", "name": "leaf"}]},
            {"file": "b.c", "name": "hi", "callees": [{"file": "c.c", "name": "leaf"}]},
            {"file": "c.c", "name": "leaf"},
        ]
        adj = build_adjacency_from_gaps(gaps)
        scores = {"a.c:lo": 1, "b.c:hi": 20}
        result = merge_with_priority(adj, gaps, priority_scores=scores)
        names = [g["name"] for g in result]
        assert names[0] == "leaf"
        assert names.index("hi") < names.index("lo")


class TestResolveSCCSummaries:
    def test_single_node_scc(self):
        scc = SCC(members=frozenset({"a"}), is_cycle=False)
        adj = {"a": []}
        call_count = [0]

        def build(key, callee_sums):
            call_count[0] += 1
            return {"key": key, "flows": []}

        result = resolve_scc_summaries(scc, adj, build)
        assert "a" in result
        assert result["a"]["converged"]
        assert result["a"]["iterations"] == 1
        assert call_count[0] == 1

    def test_two_node_cycle_converges(self):
        scc = SCC(members=frozenset({"a", "b"}), is_cycle=True)
        adj = {"a": ["b"], "b": ["a"]}
        iteration_tracker = [0]

        def build(key, callee_sums):
            iteration_tracker[0] += 1
            if callee_sums.get("a") is not None or callee_sums.get("b") is not None:
                return {"key": key, "stable": True}
            return {"key": key, "stable": False}

        result = resolve_scc_summaries(scc, adj, build)
        assert result["a"]["converged"]
        assert result["b"]["converged"]
        assert result["a"]["iterations"] <= 3

    def test_non_converging_marked(self):
        scc = SCC(members=frozenset({"a", "b"}), is_cycle=True)
        adj = {"a": ["b"], "b": ["a"]}
        counter = [0]

        def build(key, callee_sums):
            counter[0] += 1
            return {"key": key, "iter": counter[0]}

        result = resolve_scc_summaries(scc, adj, build, max_iterations=3)
        assert not result["a"]["converged"]
        assert result["a"]["iterations"] == 3

    def test_converges_on_second_iteration(self):
        scc = SCC(members=frozenset({"a", "b"}), is_cycle=True)
        adj = {"a": ["b"], "b": ["a"]}
        call_count = [0]

        def build(key, callee_sums):
            call_count[0] += 1
            return {"key": key, "value": "fixed"}

        result = resolve_scc_summaries(scc, adj, build)
        assert result["a"]["converged"]
        assert result["a"]["iterations"] == 2

    def test_callee_summaries_passed_correctly(self):
        scc = SCC(members=frozenset({"a", "b"}), is_cycle=True)
        adj = {"a": ["b"], "b": ["a"]}
        received_callees = []

        def build(key, callee_sums):
            received_callees.append((key, dict(callee_sums)))
            return {"key": key}

        resolve_scc_summaries(scc, adj, build, max_iterations=1)
        a_calls = [c for k, c in received_callees if k == "a"]
        assert len(a_calls) >= 1
        assert "b" in a_calls[0]

    def test_to_dict_summaries_compared(self):
        scc = SCC(members=frozenset({"a", "b"}), is_cycle=True)
        adj = {"a": ["b"], "b": ["a"]}

        class FakeSummary:
            def __init__(self, val):
                self.val = val

            def to_dict(self):
                return {"val": self.val}

        def build(key, callee_sums):
            return FakeSummary("stable")

        result = resolve_scc_summaries(scc, adj, build)
        assert result["a"]["converged"]
        assert result["a"]["summary"].val == "stable"

    def test_three_node_cycle(self):
        scc = SCC(members=frozenset({"a", "b", "c"}), is_cycle=True)
        adj = {"a": ["b"], "b": ["c"], "c": ["a"]}

        def build(key, callee_sums):
            return {"key": key, "has_callees": bool(callee_sums)}

        result = resolve_scc_summaries(scc, adj, build)
        assert len(result) == 3
        for member in ("a", "b", "c"):
            assert member in result


# ---------------------------------------------------------------------------
# Iterative Tarjan robustness — must not recurse, must match the
# classic recursive formulation exactly.
# ---------------------------------------------------------------------------


def _recursive_reference_sccs(adj):
    """Reference implementation: the original recursive Tarjan.

    Kept verbatim (modulo the counter cell) so the iterative rewrite
    can be pinned against it on small graphs where recursion is safe.
    """
    index_counter = [0]
    stack = []
    on_stack = set()
    indices = {}
    lowlinks = {}
    result = []

    all_nodes = set(adj)
    for targets in adj.values():
        all_nodes.update(targets)

    def strongconnect(v):
        indices[v] = lowlinks[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack.add(v)

        for w in adj.get(v, []):
            if w not in indices:
                strongconnect(w)
                lowlinks[v] = min(lowlinks[v], lowlinks[w])
            elif w in on_stack:
                lowlinks[v] = min(lowlinks[v], indices[w])

        if lowlinks[v] == indices[v]:
            members = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                members.append(w)
                if w == v:
                    break
            frozen = frozenset(members)
            is_cycle = len(frozen) > 1 or (
                len(frozen) == 1 and v in adj.get(v, [])
            )
            result.append(SCC(members=frozen, is_cycle=is_cycle))

    for node in sorted(all_nodes):
        if node not in indices:
            strongconnect(node)

    return result


class TestDetectSCCsIterative:
    def test_deep_linear_chain_completes(self):
        """A call chain longer than the recursion limit must not
        raise RecursionError (the recursive formulation died here)."""
        n = 100_000
        adj = {f"n{i:06d}": [f"n{i + 1:06d}"] for i in range(n)}
        sccs = detect_sccs(adj)
        assert len(sccs) == n + 1
        assert all(len(s) == 1 and not s.is_cycle for s in sccs)
        # Reverse topological: the chain's tail comes out first.
        assert sccs[0].members == frozenset({f"n{n:06d}"})

    def test_deep_chain_of_two_cycles(self):
        """Deep recursion through SCC back-edges, not just tree edges."""
        n = 30_000
        adj = {}
        for i in range(n):
            adj[f"a{i:06d}"] = [f"b{i:06d}"]
            adj[f"b{i:06d}"] = [f"a{i:06d}"] + (
                [f"a{i + 1:06d}"] if i + 1 < n else []
            )
        sccs = detect_sccs(adj)
        assert len(sccs) == n
        assert all(len(s) == 2 and s.is_cycle for s in sccs)

    def test_matches_recursive_reference_on_random_graphs(self):
        """Randomised equivalence: identical SCC membership, cycle
        flags, AND emission order versus the recursive original."""
        import random

        rng = random.Random(0xA0D17)
        for _ in range(200):
            n = rng.randint(1, 14)
            nodes = [f"f{i}" for i in range(n)]
            adj = {}
            for v in nodes:
                if rng.random() < 0.85:
                    degree = rng.randint(0, min(n, 4))
                    # Duplicates and self-loops are intentionally
                    # possible — real call graphs carry both.
                    adj[v] = [rng.choice(nodes) for _ in range(degree)]
            assert detect_sccs(adj) == _recursive_reference_sccs(adj)

    def test_matches_reference_on_structured_graphs(self):
        cases = [
            {},
            {"a": []},
            {"a": ["a"]},
            {"a": ["b"], "b": ["c"], "c": ["a"], "d": ["c", "e"], "e": ["d"]},
            {"a": ["b", "b", "a"], "b": ["a"]},
            {"a": ["b"], "c": ["d"]},  # disconnected components
        ]
        for adj in cases:
            assert detect_sccs(adj) == _recursive_reference_sccs(adj)
