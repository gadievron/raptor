"""Lengauer–Tarjan dominator tree — Phase 5a of the sanitizer-cut arc.

A *dominator tree* over a flow graph rooted at ``entry`` answers the
question "which nodes lie on every path from ``entry`` to ``v``?".
Phase 6 will intersect the dominator set of a sink with the
sanitizer catalogue to find candidate sanitizers; Phase 7's
vertex-cut suppression check is BFS-after-deletion, but the
candidate-enumeration step is dominator-based.

This module is the graph-theory substrate the rest of Project B
sits on. It is generic over node identifiers (anything hashable
that implements ``__eq__``) and consumes an opaque ``Graph``
protocol so the same dominator code services Python intra-
procedural CFGs (phase 5b), C/C++ inter-procedural call graphs
(phase 5b), and any other flow-graph producer that arrives later.

Algorithm: Lengauer & Tarjan, *A Fast Algorithm for Finding
Dominators in a Flowgraph*, ACM TOPLAS 1(1), 1979.  The "simple"
union-find variant is implemented (O(E·log V) practical, O(E·α(E))
amortised with path-compression). The more complex O(E·α(E))
worst-case variant in §3 of the paper adds a balanced-trees
substrate that's not worth the complexity for the flow-graph sizes
RAPTOR sees (intra-procedural CFGs: typically <1k nodes;
call graphs: typically <50k nodes).

Unreachable nodes (no path from ``entry``) are dropped silently
from the resulting tree — they cannot be dominated and would
violate L–T's preconditions. A logged-count diagnostic surfaces
the prune.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import (
    Callable,
    Dict,
    Generic,
    Hashable,
    Iterable,
    List,
    Optional,
    Protocol,
    Set,
    TypeVar,
    runtime_checkable,
)


logger = logging.getLogger(__name__)


N = TypeVar("N", bound=Hashable)


@runtime_checkable
class Graph(Protocol[N]):
    """Minimal flow-graph protocol the dominator builder needs.

    ``entry`` is the unique source of all paths analysed; nodes
    unreachable from ``entry`` are silently pruned. ``nodes()``
    yields every node identifier exactly once (order doesn't matter
    — the L–T DFS will re-order). ``successors(n)`` yields the
    children of ``n`` in flow-graph direction (call-graph edges,
    CFG edges, etc.). Predecessors are computed internally from
    successor walks; the producer doesn't need to maintain a reverse
    index.
    """

    @property
    def entry(self) -> N: ...

    def nodes(self) -> Iterable[N]: ...

    def successors(self, node: N) -> Iterable[N]: ...


# ---------------------------------------------------------------------------
# DomTree — query surface
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DomTree(Generic[N]):
    """Immediate-dominator table plus convenience queries.

    Construct via :func:`build_dom_tree`. All queries are O(d) where
    ``d`` is the depth of the dominator tree (path length from
    ``entry`` to the queried node) — no pathological case in
    practice for the graph sizes RAPTOR sees.
    """

    entry: N
    # idom[v] is the immediate dominator of v. idom[entry] is the
    # entry itself by convention (a node "dominates itself" but
    # has no proper immediate dominator). Unreachable nodes from
    # entry are NOT present in this map.
    idoms: Dict[N, N]

    def idom(self, node: N) -> Optional[N]:
        """Immediate dominator of ``node``. Returns ``None`` for
        ``entry`` (which has no proper dominator) and for any node
        that wasn't reachable from ``entry`` during construction."""
        if node not in self.idoms:
            return None
        parent = self.idoms[node]
        if parent == node:
            # By construction idoms[entry] == entry — distinguish
            # this from the "node is unreachable" case by returning
            # None here (no proper immediate dominator).
            return None
        return parent

    def dominates(self, a: N, b: N) -> bool:
        """True iff ``a`` dominates ``b`` (every path from entry to
        ``b`` passes through ``a``). Reflexive: every node
        dominates itself."""
        if a not in self.idoms or b not in self.idoms:
            return False
        cur: Optional[N] = b
        while cur is not None:
            if cur == a:
                return True
            nxt = self.idoms[cur]
            if nxt == cur:
                # Reached entry without seeing a
                return False
            cur = nxt
        return False

    def dominators_of(self, node: N) -> List[N]:
        """All dominators of ``node`` from ``entry`` (inclusive)
        down to ``node`` (inclusive). Returns ``[]`` for unreachable
        nodes."""
        if node not in self.idoms:
            return []
        path: List[N] = []
        cur: Optional[N] = node
        while cur is not None:
            path.append(cur)
            nxt = self.idoms[cur]
            if nxt == cur:
                break
            cur = nxt
        path.reverse()
        return path

    def nodes(self) -> Iterable[N]:
        """Every node in the dominator tree (i.e. every node
        reachable from entry)."""
        return self.idoms.keys()


# ---------------------------------------------------------------------------
# Builder — Lengauer–Tarjan, simple variant
# ---------------------------------------------------------------------------


def _dfs_number(
    entry: N, successors: Callable[[N], Iterable[N]],
) -> tuple[List[N], Dict[N, int], Dict[N, N]]:
    """Iterative DFS numbering.

    Returns:
        vertex — list ``i -> node`` in DFS discovery order; ``vertex[0]``
            is the entry.
        dfnum  — map ``node -> i`` (inverse of ``vertex``).
        parent — DFS spanning tree parent of each non-entry node.

    Iterative because RAPTOR scans large repos: recursive DFS on
    pathological CFGs (long try-with chains in big Python files)
    hits the default 1000-frame recursion limit on cpython.
    """
    vertex: List[N] = []
    dfnum: Dict[N, int] = {}
    parent: Dict[N, N] = {}
    stack: List[tuple[N, Optional[N], Iterable[N]]] = [
        (entry, None, iter(successors(entry))),
    ]
    dfnum[entry] = 0
    vertex.append(entry)
    while stack:
        node, _, succ_iter = stack[-1]
        advanced = False
        for child in succ_iter:
            if child in dfnum:
                continue
            dfnum[child] = len(vertex)
            vertex.append(child)
            parent[child] = node
            stack.append((child, node, iter(successors(child))))
            advanced = True
            break
        if not advanced:
            stack.pop()
    return vertex, dfnum, parent


class _UnionFind(Generic[N]):
    """Path-compression union-find for the L–T eval/link operations.

    Stores ``ancestor`` (the up-pointer) and ``label`` (the
    semidominator-minimising node seen on the path). Each ``link``
    just sets ``ancestor[v] = w``; each ``eval`` walks up and
    path-compresses while tracking the minimum-semi label.
    """

    def __init__(self, semi: Dict[N, int]):
        self._semi = semi
        self._ancestor: Dict[N, Optional[N]] = {}
        self._label: Dict[N, N] = {}

    def make(self, node: N) -> None:
        self._ancestor[node] = None
        self._label[node] = node

    def link(self, v: N, w: N) -> None:
        self._ancestor[w] = v

    def _compress(self, v: N) -> None:
        # Iterative compression: build the path up to a root, then
        # rewrite each ancestor[u] = root and pick the
        # minimum-semi label along the way.
        path: List[N] = []
        cur: Optional[N] = v
        while cur is not None and self._ancestor.get(cur) is not None:
            path.append(cur)
            cur = self._ancestor[cur]
        if not path:
            return
        # ``path`` ends at a node whose ancestor is None or the root;
        # walk it tail→head so each ancestor points to ``path[-1]``'s
        # ancestor and labels propagate from leaves up.
        for i in range(len(path) - 1, 0, -1):
            u = path[i]
            parent_u = self._ancestor[u]
            if parent_u is None:
                continue
            if (parent_u in self._label
                    and self._semi[self._label[parent_u]]
                    < self._semi[self._label[u]]):
                # The parent's label has a smaller semidominator —
                # propagate it down so the deeper node also sees the
                # minimum.
                pass  # handled by below walk on `u`
            up = path[i - 1]
            # Path-compress: rewrite up's ancestor to point past u.
            if (self._ancestor.get(u) is not None
                    and self._semi[self._label[self._ancestor[u]]]
                    < self._semi[self._label[up]]):
                self._label[up] = self._label[self._ancestor[u]]
            self._ancestor[up] = self._ancestor[u]

    def eval(self, v: N) -> N:
        """Return the node ``u`` on the path ``v → root`` whose
        ``semi[u]`` is minimum."""
        if self._ancestor.get(v) is None:
            return v
        self._compress(v)
        return self._label[v]


def build_dom_tree(graph: Graph[N]) -> DomTree[N]:
    """Compute the dominator tree of ``graph`` rooted at ``graph.entry``.

    Implements Lengauer–Tarjan §3 simple union-find variant.
    Nodes unreachable from ``entry`` are silently dropped (logged at
    DEBUG with a count). Returns a :class:`DomTree` that supports
    ``idom``, ``dominates``, and ``dominators_of`` queries.

    Complexity: O(E·log V) practical, O(E·α(E)) amortised on
    typical flow graphs. Acceptable for the < 50k-node regime
    RAPTOR sees.
    """
    entry = graph.entry
    # Phase 1: DFS numbering of reachable nodes
    vertex, dfnum, parent = _dfs_number(entry, graph.successors)
    n = len(vertex)
    if n == 0:
        return DomTree(entry=entry, idoms={})
    # ``semi[v]`` is the DFS number of v's semidominator; initially v itself.
    semi: Dict[N, int] = {v: dfnum[v] for v in vertex}
    # ``bucket[w]`` collects vertices whose semidominator is ``w``.
    bucket: Dict[N, Set[N]] = {v: set() for v in vertex}
    # ``dom`` is the immediate dominator under construction.
    dom: Dict[N, N] = {entry: entry}
    # Pre-compute predecessor edges via one successor walk over reachable nodes.
    preds: Dict[N, List[N]] = {v: [] for v in vertex}
    reachable = set(vertex)
    for v in vertex:
        for s in graph.successors(v):
            if s in reachable:
                preds[s].append(v)
    # Total nodes in the graph for the dropped-node diagnostic.
    try:
        total_nodes = sum(1 for _ in graph.nodes())
    except Exception:                                       # noqa: BLE001
        total_nodes = n
    if total_nodes > n:
        logger.debug(
            "build_dom_tree: dropped %d unreachable nodes (kept %d/%d)",
            total_nodes - n, n, total_nodes,
        )

    uf: _UnionFind[N] = _UnionFind(semi)
    for v in vertex:
        uf.make(v)

    # Phase 2: walk vertices in reverse DFS order; compute semidominators.
    for i in range(n - 1, 0, -1):
        w = vertex[i]
        # 2a: semi(w) = min(semi(eval(u)) for u in preds(w))
        for u in preds[w]:
            candidate = semi[uf.eval(u)]
            if candidate < semi[w]:
                semi[w] = candidate
        bucket[vertex[semi[w]]].add(w)
        # 2b: link w to its parent.
        uf.link(parent[w], w)
        # 2c: process w's parent's bucket — finalise idom for each
        # vertex whose semidominator is w's parent (or earlier).
        p = parent[w]
        for v in list(bucket[p]):
            bucket[p].discard(v)
            u = uf.eval(v)
            dom[v] = u if semi[u] < semi[v] else p

    # Phase 3: explicit pass to finalise immediate dominators where
    # the semidominator was deferred (dom[w] needs to chase up the
    # tree until it matches semi[w]).
    for i in range(1, n):
        w = vertex[i]
        if dom.get(w) != vertex[semi[w]]:
            dom[w] = dom[dom[w]]

    return DomTree(entry=entry, idoms=dom)


# ---------------------------------------------------------------------------
# Convenience: build a graph from raw successors mapping
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdjacencyGraph(Generic[N]):
    """In-memory adjacency-list implementation of :class:`Graph`.

    Convenience for callers (and tests) that already have a
    ``{node: [successors]}`` map and don't want to write a custom
    ``Graph`` subclass. The successors map is the ground truth — if
    you list a node only as a successor and never as a key with an
    entry of its own, it's considered a leaf (no outgoing edges).
    """

    entry: N
    adjacency: Dict[N, List[N]]

    def nodes(self) -> Iterable[N]:
        seen: Set[N] = set()
        for k, vs in self.adjacency.items():
            if k not in seen:
                seen.add(k)
                yield k
            for v in vs:
                if v not in seen:
                    seen.add(v)
                    yield v

    def successors(self, node: N) -> Iterable[N]:
        return self.adjacency.get(node, ())


__all__ = [
    "Graph",
    "DomTree",
    "AdjacencyGraph",
    "build_dom_tree",
]
