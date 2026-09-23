"""Shared size-cap discipline for diagram generators.

flow_trace landed the pattern — bounded element counts plus a LOUD
truncation marker naming the dropped count and the cap — after
unbounded inputs produced diagrams that hang browsers, trip Mermaid's
own "diagram too complex" limit, and blow markdown tools' size
budgets so reports truncate at the wrong place. Inputs are LLM/run
artifacts: nothing upstream bounds them. This module is the one home
for that pattern so sibling generators adopt a discipline instead of
re-deriving (or skipping) it.

Cap values are per-generator judgement calls, but the trade-off is
the same everywhere: higher caps keep more of a legitimately large
artifact visible at the cost of re-opening the oversize failure
modes; lower caps render snappily but hide structure sooner. 200
elements is the largest size that renders cleanly in mainstream
Mermaid setups (flow_trace's measured value); markdown-level path
sections use smaller caps because each element is a whole diagram.
Truncation is NEVER silent — every cap that fires emits a marker.
"""

from __future__ import annotations

#: Default per-list element cap (flow_trace's measured Mermaid limit).
DEFAULT_CAP = 200


def cap_elements(items: list, cap: int = DEFAULT_CAP) -> tuple[list, int]:
    """Return ``(bounded_items, dropped_count)``."""
    if len(items) > cap:
        return items[:cap], len(items) - cap
    return items, 0


def truncation_marker_lines(
    node_id: str, dropped: int, what: str, cap: int,
) -> list[str]:
    """Mermaid lines announcing a truncation — the loud half of the
    cap. Empty when nothing was dropped. Same node text/style as
    flow_trace's original marker so operators see one idiom."""
    if dropped <= 0:
        return []
    return [
        "",
        f'    {node_id}["⚠ Diagram truncated: '
        f'{dropped} additional {what} not shown '
        f'(cap {cap})"]',
        f"    style {node_id} fill:#fef9c3,stroke:#a16207",
    ]


__all__ = ["DEFAULT_CAP", "cap_elements", "truncation_marker_lines"]
