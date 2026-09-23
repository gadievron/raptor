"""Shared CFG utility functions."""

from __future__ import annotations


def find_node_at_line(cfg, line: int):
    """Find the CFG node at or nearest to the given line — bounded to
    the graph's real line span.

    A line outside ``[min, max]`` of the statement nodes' linenos
    returns ``None`` instead of silently attributing the nearest
    node's facts (guards, defs) to code the graph never modelled.
    Entry/exit sentinels (negative linenos) are excluded from both
    the span and the match.
    """
    best = None
    best_dist = float("inf")
    lo: int | None = None
    hi: int | None = None
    for node in cfg.nodes():
        ln = node.lineno
        if ln < 0:
            continue
        lo = ln if lo is None else min(lo, ln)
        hi = ln if hi is None else max(hi, ln)
        dist = abs(ln - line)
        if dist < best_dist:
            best_dist = dist
            best = node
    if lo is None or hi is None or not (lo <= line <= hi):
        return None
    return best
