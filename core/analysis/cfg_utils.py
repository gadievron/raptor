"""Shared CFG utility functions."""

from __future__ import annotations


def find_node_at_line(cfg, line: int):
    """Find the CFG node at or nearest to the given line."""
    best = None
    best_dist = float("inf")
    for node in cfg.nodes():
        dist = abs(node.lineno - line)
        if dist < best_dist:
            best_dist = dist
            best = node
    return best
