"""Topological ordering of the call graph for bottom-up summary propagation.

Extracts the project call graph (from Joern CPG or a supplied adjacency dict),
detects strongly connected components via Tarjan's algorithm, and returns a
processing order where callees come before callers.  Within an SCC the order
is by priority score so higher-risk functions are summarised first.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SCC:
    """A strongly connected component in the call graph."""

    members: frozenset[str]
    is_cycle: bool

    def __len__(self) -> int:
        return len(self.members)


def detect_sccs(adj: dict[str, list[str]]) -> list[SCC]:
    """Tarjan's algorithm for strongly connected components.

    Args:
        adj: adjacency list  {caller: [callees]}.  Keys that appear only as
             callees are treated as leaf nodes (no outgoing edges).

    Returns:
        SCCs in reverse topological order (leaves first).
    """
    index_counter = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    result: list[SCC] = []

    all_nodes: set[str] = set(adj)
    for targets in adj.values():
        all_nodes.update(targets)

    # Iterative Tarjan with an explicit work stack (same pattern as
    # task_graph._break_cycles' DFS). The recursive formulation blew
    # the interpreter recursion limit on call chains deeper than
    # ~1000 edges — a linear chain in a large target killed the audit
    # from both orchestrator call sites. Each work-stack frame is
    # ``(node, next_neighbour_index)`` so a child visit suspends the
    # parent exactly where recursion would.
    for root in sorted(all_nodes):
        if root in indices:
            continue

        work: list[list] = [[root, 0]]
        while work:
            frame = work[-1]
            v, edge_idx = frame

            if edge_idx == 0:
                indices[v] = lowlinks[v] = index_counter
                index_counter += 1
                stack.append(v)
                on_stack.add(v)

            neighbours = adj.get(v, [])
            descended = False
            while edge_idx < len(neighbours):
                w = neighbours[edge_idx]
                edge_idx += 1
                if w not in indices:
                    frame[1] = edge_idx
                    work.append([w, 0])
                    descended = True
                    break
                if w in on_stack:
                    lowlinks[v] = min(lowlinks[v], indices[w])
            if descended:
                continue

            # All neighbours explored — this is the point where the
            # recursive strongconnect(v) would return.
            work.pop()
            if lowlinks[v] == indices[v]:
                members: list[str] = []
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
            if work:
                parent = work[-1][0]
                lowlinks[parent] = min(lowlinks[parent], lowlinks[v])

    return result


def topological_sort(
    adj: dict[str, list[str]],
    *,
    priority_scores: dict[str, float] | None = None,
) -> list[str]:
    """Return functions in bottom-up order (leaves first, roots last).

    Within the same topological level, functions are ordered by priority
    score descending (highest-priority first within the same level).
    Within an SCC, members are ordered by priority score.

    Args:
        adj: call graph adjacency list {caller: [callees]}.
        priority_scores: optional {function_key: score} for tie-breaking.

    Returns:
        Function keys in processing order.
    """
    sccs = detect_sccs(adj)
    if not sccs:
        return []

    scores = priority_scores or {}

    node_to_scc: dict[str, int] = {}
    for i, scc in enumerate(sccs):
        for m in scc.members:
            node_to_scc[m] = i

    # Build reversed condensed DAG (callee→caller) so Kahn's gives
    # leaves first — the bottom-up order we need for summary propagation.
    rev_adj: dict[int, set[int]] = {i: set() for i in range(len(sccs))}
    in_degree: dict[int, int] = {i: 0 for i in range(len(sccs))}
    for node, neighbours in adj.items():
        src = node_to_scc.get(node)
        if src is None:
            continue
        for nb in neighbours:
            dst = node_to_scc.get(nb)
            if dst is not None and dst != src and src not in rev_adj[dst]:
                rev_adj[dst].add(src)
                in_degree[src] += 1

    def _scc_score(idx: int) -> float:
        return max((scores.get(m, 0) for m in sccs[idx].members), default=0)

    import heapq

    ready = [(-_scc_score(i), i) for i in range(len(sccs)) if in_degree[i] == 0]
    heapq.heapify(ready)

    ordered: list[str] = []
    while ready:
        _, scc_idx = heapq.heappop(ready)
        members = sorted(
            sccs[scc_idx].members,
            key=lambda k: scores.get(k, 0),
            reverse=True,
        )
        ordered.extend(members)
        for neighbour in rev_adj[scc_idx]:
            in_degree[neighbour] -= 1
            if in_degree[neighbour] == 0:
                heapq.heappush(ready, (-_scc_score(neighbour), neighbour))

    return ordered


def resolve_scc_summaries(
    scc: SCC,
    adj: dict[str, list[str]],
    build_fn: Any,
    *,
    max_iterations: int = 3,
) -> dict[str, Any]:
    """Iterative fixed-point convergence for summaries within an SCC.

    For mutually-recursive functions (A calls B, B calls A), summaries
    can't be built in one pass because each depends on the other.  This
    runs the abstract-interpretation fixed-point loop:

    1. Start with empty summaries for all SCC members
    2. Call build_fn(member_key, callee_summaries) for each member
    3. Compare with previous iteration
    4. Repeat until stable or max_iterations reached

    Args:
        scc: The strongly connected component to resolve.
        adj: Full call graph adjacency (used to find intra-SCC edges).
        build_fn: Callable(function_key, callee_summaries_dict) -> summary.
            The summary can be any object with a to_dict() method (for
            comparison) or any JSON-serialisable value.
        max_iterations: Stop after this many rounds even if not converged.

    Returns:
        {function_key: {"summary": summary, "converged": bool, "iterations": int}}
    """
    if not scc.is_cycle:
        member = next(iter(scc.members))
        summary = build_fn(member, {})
        return {member: {"summary": summary, "converged": True, "iterations": 1}}

    current: dict[str, Any] = {m: None for m in scc.members}
    converged = False
    iteration = 0

    for iteration in range(1, max_iterations + 1):
        previous_serialised = _serialise_summaries(current)
        new_summaries: dict[str, Any] = {}

        for member in sorted(scc.members):
            callee_summaries: dict[str, Any] = {}
            for callee in adj.get(member, []):
                if callee in scc.members:
                    new_val = new_summaries.get(callee)
                    callee_summaries[callee] = (
                        new_val
                        if new_val is not None
                        else current.get(callee)
                    )
            new_summaries[member] = build_fn(member, callee_summaries)

        current = new_summaries
        current_serialised = _serialise_summaries(current)

        if current_serialised == previous_serialised:
            converged = True
            break

    return {
        m: {
            "summary": current[m],
            "converged": converged,
            "iterations": iteration,
        }
        for m in scc.members
    }


def _serialise_summaries(summaries: dict[str, Any]) -> str:
    """Serialise summaries for comparison between iterations."""
    import json
    stable = {}
    for k, v in sorted(summaries.items()):
        if v is None:
            stable[k] = None
        elif hasattr(v, "to_dict"):
            stable[k] = v.to_dict()
        else:
            stable[k] = v
    return json.dumps(stable, sort_keys=True, default=str)


def build_adjacency_from_gaps(
    gaps: Sequence[dict[str, Any]],
) -> dict[str, list[str]]:
    """Build a call-graph adjacency list from gap dicts.

    Each gap dict should have 'file', 'name', and optionally 'callees'
    (list of dicts with 'file' and 'name' keys).
    """
    adj: dict[str, list[str]] = {}
    for gap in gaps:
        key = f"{gap['file']}:{gap['name']}"
        callee_keys: list[str] = []
        for callee in gap.get("callees", []):
            cfile = callee.get("file", "")
            cname = callee.get("name", "")
            if cfile and cname:
                callee_keys.append(f"{cfile}:{cname}")
        adj[key] = callee_keys
    return adj


def merge_with_priority(
    adj: dict[str, list[str]],
    gaps: Sequence[dict[str, Any]],
    *,
    priority_scores: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    """Reorder gaps in topological (bottom-up) order.

    Returns the same gap dicts, reordered so callees come before callers.
    Gaps not present in the adjacency list are appended at the end (roots).
    """
    order = topological_sort(adj, priority_scores=priority_scores)

    gap_map: dict[str, dict[str, Any]] = {}
    for gap in gaps:
        key = f"{gap['file']}:{gap['name']}"
        gap_map[key] = gap

    result: list[dict[str, Any]] = []
    seen: set[str] = set()

    for key in order:
        if key in gap_map:
            result.append(gap_map[key])
            seen.add(key)

    for gap in gaps:
        key = f"{gap['file']}:{gap['name']}"
        if key not in seen:
            result.append(gap)

    return result
