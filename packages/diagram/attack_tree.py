"""
Mermaid diagram generator for attack-tree.json (produced by /validate Stage B).

Renders the attack knowledge graph as a top-down flowchart with node styling
by status: confirmed, disproven, exploring, unexplored, uncertain. Very much a WIP, we may want to add more details or styling, e.g. showing which nodes are confirmed vs theoretical, or adding more info about blockers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _sanitize(text: str) -> str:
    return (
        str(text)
        .replace('"', "'")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("{", "(")
        .replace("}", ")")
        .replace("\n", " ")
    )


def _node_label(node: dict[str, Any]) -> str:
    nid = node.get("id", "?")
    goal = _sanitize(node.get("goal", node.get("technique", nid)))
    technique = _sanitize(node.get("technique", ""))
    status = node.get("status", "unexplored")
    parts = [goal]
    if technique and technique != goal:
        parts.append(technique)
    parts.append(f"[{status}]")
    return "\\n".join(parts)


def _node_shape(status: str) -> tuple[str, str]:
    """Shape by status."""
    if status == "confirmed":
        return '["', '"]'
    if status == "disproven":
        return '["', '"]'
    if status in ("exploring", "uncertain"):
        return '{"', '"}'
    # unexplored
    return '("', '")'


def generate(data: dict[str, Any]) -> str:
    root_id = data.get("root")
    nodes: list[dict] = data.get("nodes", [])

    if not nodes:
        return 'flowchart TD\n    EMPTY["No attack tree nodes"]'

    # Build id → node lookup
    node_map = {n.get("id"): n for n in nodes}

    lines = ["flowchart TD"]
    lines.append("")
    lines.append("    %% Attack Tree Nodes")

    for node in nodes:
        nid = node.get("id", "?")
        status = node.get("status", "unexplored")
        label = _node_label(node)
        open_ch, close_ch = _node_shape(status)
        lines.append(f"    {nid}{open_ch}{label}{close_ch}")

    # Edges from leads_to (comma-separated string per schema)
    lines.append("")
    lines.append("    %% Edges")
    for node in nodes:
        nid = node.get("id", "?")
        leads_to_raw = node.get("leads_to", "")
        if not leads_to_raw:
            continue
        targets = [t.strip() for t in str(leads_to_raw).split(",") if t.strip()]
        for target in targets:
            if target in node_map:
                lines.append(f"    {nid} --> {target}")

    # Style by status
    status_groups: dict[str, list[str]] = {}
    for node in nodes:
        s = node.get("status", "unexplored")
        status_groups.setdefault(s, []).append(node.get("id", "?"))

    lines.append("")
    lines.append("    classDef confirmed fill:#dcfce7,stroke:#16a34a,color:#14532d")
    lines.append("    classDef disproven fill:#f1f5f9,stroke:#94a3b8,color:#64748b")
    lines.append("    classDef exploring fill:#fef9c3,stroke:#ca8a04,color:#713f12")
    lines.append("    classDef uncertain fill:#fef3c7,stroke:#d97706,color:#78350f")
    lines.append("    classDef unexplored fill:#f8fafc,stroke:#cbd5e1,color:#334155")

    for status, ids in status_groups.items():
        cls = status if status in ("confirmed", "disproven", "exploring", "uncertain", "unexplored") else "unexplored"
        lines.append(f"    class {','.join(ids)} {cls}")

    # Highlight root
    if root_id and root_id in node_map:
        lines.append(f"    style {root_id} stroke-width:3px")

    return "\n".join(lines)


def generate_from_file(path: Path) -> str:
    data = json.loads(path.read_text())
    return generate(data)
