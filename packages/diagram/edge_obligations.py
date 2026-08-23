"""Mermaid rendering for edge-obligations.json (/audit --edges).

Tier-1 edges render solid with their obligation reason; tier-2 edges
dashed (folded into caller reviews); blind spots and degradations are
summarised as notes. Bounded output with explicit "+N more" markers —
never a silent cap.
"""

from __future__ import annotations

from typing import Any

from .sanitize import sanitize as _sanitize

_MAX_TIER1 = 30
_MAX_TIER2 = 20


def _node_id(prefix: str, name: str, registry: dict) -> str:
    key = (prefix, name)
    if key not in registry:
        registry[key] = f"{prefix}{len(registry)}"
    return registry[key]


def generate(data: dict[str, Any]) -> str:
    """Flowchart of tiered edge obligations."""
    tier1 = data.get("tier1") or []
    tier2 = data.get("tier2") or []
    blind = data.get("blind_spots") or []
    stats = data.get("stats") or {}

    lines = ["flowchart LR"]
    nodes: dict = {}

    def _fn(file: str, name: str) -> str:
        nid = _node_id("f", f"{file}:{name}", nodes)
        label = _sanitize(f"{name}")
        return f'{nid}["{label}"]'

    emitted: set[str] = set()

    def _emit_node(file, name):
        decl = _fn(str(file), str(name))
        nid = decl.split("[")[0]
        if nid not in emitted:
            emitted.add(nid)
            lines.append(f"    {decl}")
        return nid

    for rec in tier1[:_MAX_TIER1]:
        a = _emit_node(rec.get("caller_file"), rec.get("caller"))
        b = _emit_node(rec.get("callee_file"), rec.get("callee"))
        reason = _sanitize(str(rec.get("reason") or "tier1"))[:40]
        lines.append(f'    {a} -->|"{reason}"| {b}')
    if len(tier1) > _MAX_TIER1:
        lines.append(
            f'    t1more["+{len(tier1) - _MAX_TIER1} more tier-1 edges"]')

    for rec in tier2[:_MAX_TIER2]:
        a = _emit_node(rec.get("caller_file"), rec.get("caller"))
        b = _emit_node(rec.get("callee_file"), rec.get("callee"))
        lines.append(f"    {a} -.->|folded| {b}")
    if len(tier2) > _MAX_TIER2:
        lines.append(
            f'    t2more["+{len(tier2) - _MAX_TIER2} more tier-2 edges"]')

    if blind:
        lines.append(
            f'    blind["Blind spots: {len(blind)} call site(s) the '
            'static graph cannot follow"]')
        lines.append("    style blind stroke-dasharray: 5 5")
    degraded = stats.get("degraded") or []
    if degraded:
        deg = _sanitize(", ".join(str(d) for d in degraded[:4]))
        lines.append(f'    deg["Degraded: {deg}"]')

    return "\n".join(lines)
