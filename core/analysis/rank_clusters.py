"""Call-graph cluster analysis over listwise-ranking output.

The localization recipe from the SiftRank paper's security evaluation
(Gross, arXiv:2512.06155 §4; see docs/references.md): after ranking
call chains against an advisory or query with ``core.llm.ranking``,
convert per-chain ranks into per-function weights and re-aggregate
the survivors into call-graph clusters, so a critical function that
ranked modestly on its own is surfaced by its high-weight neighbours.

  * Function weight: ``w_f = k_f / r_f`` where ``r_f`` is the
    function's best (lowest) rank across all chains containing it and
    ``k_f`` the maximum ranking iterations it survived — quality ×
    confidence.
  * Clusters: connected neighbourhoods of the call graph around each
    weighted function. The paper constrains clusters "by diameter"
    (values 1–3) with per-seed clusters; this module grows a BFS ball
    of ``radius`` hops around each seed (diameter ≤ 2·radius) and
    names the parameter accordingly rather than overstating it.
    Unweighted intermediate nodes conduct distance but do not join
    the cluster.
  * Cluster score: mass × density = ``(Σw)² / |C|`` — favours
    clusters that are both heavy and concentrated. The metric is
    linear in |C| at fixed mean weight, so in a FLAT-weight regime a
    big reachable blob can outscore a tight heavy cluster; the
    ``max_members`` guard (oversized balls are skipped, not
    truncated) and the conservative default radii exist to keep that
    degenerate case out of the top of the list.

Everything here is deterministic graph/arithmetic code — no LLM
calls. Intended consumers: patch-localization flows (rank changed
functions from a binary or source patch against an advisory, then
cluster to find the fix neighbourhood — e.g. when /cve-diff cannot
discover a published fix commit but a vendor patch is in hand) and
`/understand`-derived call graphs.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable

DEFAULT_RADII = (1, 2)
# Balls with more weighted members than this are not localization
# signal — they are "everything near a hub" — and are skipped rather
# than allowed to bury concentrated clusters (score is linear in |C|
# at fixed mean weight).
DEFAULT_MAX_MEMBERS = 16


@dataclass(frozen=True)
class FunctionWeight:
    name: str
    weight: float
    best_rank: int
    iterations: int


@dataclass(frozen=True)
class Cluster:
    seed: str
    radius: int
    members: tuple[str, ...]  # sorted
    mass: float
    density: float
    score: float


@dataclass
class ClusterReport:
    weights: dict[str, FunctionWeight] = field(default_factory=dict)
    clusters: list[Cluster] = field(default_factory=list)


def weight_functions(
    chains: Iterable[dict[str, Any]],
) -> dict[str, FunctionWeight]:
    """Per-function ``w = k / r`` from ranked call chains.

    Each chain dict needs ``functions`` (list of names), ``rank``
    (1-based, lower = more relevant), and ``iterations`` (ranking
    iterations survived, >= 1). Malformed chains are skipped.
    """
    best_rank: dict[str, int] = {}
    max_iter: dict[str, int] = {}
    for chain in chains:
        if not isinstance(chain, dict):
            continue
        try:
            rank = int(chain["rank"])
            raw_iterations = chain.get("iterations")
            iterations = 1 if raw_iterations is None else int(raw_iterations)
        except (KeyError, TypeError, ValueError):
            continue
        if rank < 1 or iterations < 1:
            continue
        functions = chain.get("functions") or []
        if isinstance(functions, (str, bytes)):
            continue  # a bare string would explode into characters
        for name in functions:
            name = str(name)
            if not name:
                continue
            if rank < best_rank.get(name, rank + 1):
                best_rank[name] = rank
            if iterations > max_iter.get(name, 0):
                max_iter[name] = iterations
    return {
        name: FunctionWeight(
            name=name,
            weight=max_iter[name] / best_rank[name],
            best_rank=best_rank[name],
            iterations=max_iter[name],
        )
        for name in best_rank
    }


def _adjacency(
    edges: Iterable[tuple[str, str]],
) -> dict[str, set[str]]:
    adj: dict[str, set[str]] = {}
    for a, b in edges:
        a, b = str(a), str(b)
        if not a or not b or a == b:
            continue
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)
    return adj


def _ball(
    seed: str, adj: dict[str, set[str]], radius: int,
) -> set[str]:
    """Nodes within ``radius`` undirected hops of ``seed``."""
    seen = {seed}
    frontier = deque([(seed, 0)])
    while frontier:
        node, dist = frontier.popleft()
        if dist == radius:
            continue
        for neighbour in adj.get(node, ()):
            if neighbour not in seen:
                seen.add(neighbour)
                frontier.append((neighbour, dist + 1))
    return seen


def rank_clusters(
    chains: Iterable[dict[str, Any]],
    edges: Iterable[tuple[str, str]],
    *,
    radii: Iterable[int] = DEFAULT_RADII,
    max_members: int = DEFAULT_MAX_MEMBERS,
) -> ClusterReport:
    """Weight functions from ranked chains, cluster on the call graph.

    ``edges`` is the call graph as (caller, callee) pairs; direction
    is ignored for proximity, and functions absent from the ranked
    chains conduct distance without joining clusters. Clusters are
    grown per weighted seed for each radius, pooled, deduplicated by
    member set (keeping the smallest radius that produced the set),
    and sorted by score descending (ties: smaller cluster, then seed
    name, for determinism).
    """
    weights = weight_functions(chains)
    report = ClusterReport(weights=weights)
    if not weights:
        return report
    adj = _adjacency(edges)

    seen_members: dict[tuple[str, ...], Cluster] = {}
    for radius in sorted(set(int(r) for r in radii)):
        if radius < 1:
            continue
        for seed in weights:
            reachable = _ball(seed, adj, radius)
            members = tuple(sorted(n for n in reachable if n in weights))
            if not members or len(members) > max_members:
                continue
            if members in seen_members:
                continue
            mass = sum(weights[n].weight for n in members)
            density = mass / len(members)
            seen_members[members] = Cluster(
                seed=seed,
                radius=radius,
                members=members,
                mass=mass,
                density=density,
                score=mass * density,
            )

    report.clusters = sorted(
        seen_members.values(),
        key=lambda c: (-c.score, len(c.members), c.seed),
    )
    return report


__all__ = [
    "Cluster",
    "ClusterReport",
    "DEFAULT_RADII",
    "FunctionWeight",
    "rank_clusters",
    "weight_functions",
]
