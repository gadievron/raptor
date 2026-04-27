"""
Mermaid diagram generator for attack-tree.json (produced by /validate Stage B).

Renders the attack knowledge graph as a top-down flowchart. When companion
files (attack-paths.json, disproven.json, hypotheses.json) are available,
confirmed nodes are annotated with their best proximity score and disproven
nodes show why they were ruled out.

Multiple top-level findings are separated into Mermaid subgraph blocks.

WIP: we may want to add more details or styling, e.g. showing which nodes
are confirmed vs theoretical, or adding more info about blockers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.json import load_json
from .sanitize import sanitize as _sanitize, sanitize_id as _sid


_PROXIMITY_LABEL = {
    (0, 1): "theoretical",
    (2, 3): "flow confirmed, blocked",
    (4, 5): "partial bypass",
    (6, 7): "primitive confirmed",
    (8, 9): "working PoC",
    (10, 10): "reliable",
}


def _proximity_desc(score: int) -> str:
    for (lo, hi), label in _PROXIMITY_LABEL.items():
        if lo <= score <= hi:
            return label
    return ""


def _build_proximity_index(attack_paths: list[dict]) -> dict[str, int]:
    """Return finding_id → best proximity score across all paths."""
    index: dict[str, int] = {}
    for path in attack_paths:
        fid = path.get("finding") or path.get("finding_id", "")
        score = path.get("proximity", 0)
        try:
            score = int(score)
        except (TypeError, ValueError):
            score = 0
        if fid and score > index.get(fid, -1):
            index[fid] = score
    return index


def _build_disproven_index(disproven_list: list[dict]) -> dict[str, str]:
    """Return finding_id → why_wrong (first entry wins)."""
    index: dict[str, str] = {}
    for entry in disproven_list:
        fid = entry.get("finding", "")
        reason = entry.get("why_wrong", entry.get("lesson", ""))
        if fid and fid not in index and reason:
            index[fid] = reason
    return index


def _build_hypothesis_index(hypotheses: list[dict]) -> dict[str, str]:
    """Return finding_id → hypothesis status summary."""
    index: dict[str, str] = {}
    for h in hypotheses:
        fid = h.get("finding") or h.get("finding_id", "")
        status = _sanitize(h.get("status", ""))
        claim = h.get("claim") or h.get("hypothesis", "")
        if fid and fid not in index:
            index[fid] = f"{status}: {_sanitize(claim[:60])}" if claim else status
    return index


def _node_label(node: dict, proximity_idx: dict, disproven_idx: dict) -> str:
    nid = node.get("id", "?")
    goal = _sanitize(node.get("goal", node.get("technique", nid)))
    technique = _sanitize(node.get("technique", ""))
    status = _sanitize(node.get("status", "unexplored"))
    parts = [goal]
    if technique and technique != goal:
        parts.append(technique)

    # Proximity annotation on confirmed nodes
    if status == "confirmed" and nid in proximity_idx:
        score = proximity_idx[nid]
        desc = _proximity_desc(score)
        parts.append(f"proximity {score}/10,{desc}" if desc else f"proximity {score}/10")

    # Why-wrong annotation on disproven nodes
    if status == "disproven" and nid in disproven_idx:
        reason = _sanitize(disproven_idx[nid])
        short = reason if len(reason) <= 60 else reason[:57] + "..."
        parts.append(f"ruled out: {short}")

    parts.append(f"[{status}]")
    return "\\n".join(parts)


def _node_shape(status: str) -> tuple[str, str]:
    if status == "confirmed":
        return '["', '"]'
    if status == "disproven":
        return '["', '"]'
    if status in ("exploring", "uncertain"):
        return '{"', '"}'
    return '("', '")'


def _find_subgraph_groups(
    nodes: list[dict],
    root_id: str | None,
) -> dict[str, list[str]] | None:
    """
    If the root has multiple children that themselves have children, group
    into subgraphs by those children. Returns {child_id: [descendant_ids]}
    or None if the tree is too flat to bother.
    """
    node_map = {n["id"]: n for n in nodes}

    def children_of(nid: str) -> list[str]:
        raw = node_map.get(nid, {}).get("leads_to", "") or ""
        return [t.strip() for t in raw.split(",") if t.strip() and t.strip() in node_map]

    def descendants(nid: str) -> list[str]:
        result = []
        for child in children_of(nid):
            result.append(child)
            result.extend(descendants(child))
        return result

    if not root_id or root_id not in node_map:
        return None

    root_children = children_of(root_id)
    # Only use subgraphs if the root has 2+ children that have their own children
    eligible = [c for c in root_children if children_of(c)]
    if len(eligible) < 2:
        return None

    groups: dict[str, list[str]] = {}
    for child in root_children:
        desc = descendants(child)
        if desc:
            groups[child] = desc
        else:
            # Leaf child,keep ungrouped by putting it in its own single-item group
            groups[child] = []

    return groups if len(groups) >= 2 else None


def generate(
    data: dict[str, Any],
    attack_paths: list[dict] | None = None,
    disproven: list[dict] | None = None,
    hypotheses: list[dict] | None = None,
) -> str:
    root_id = _sid(data.get("root", "ROOT"))
    nodes: list[dict] = data.get("nodes", [])

    if not nodes:
        return 'flowchart TD\n    EMPTY["No attack tree nodes"]'

    # Sanitize all node IDs upfront to prevent Mermaid markup injection
    for n in nodes:
        n["id"] = _sid(n.get("id", "?"))
    node_map = {n["id"]: n for n in nodes}

    # Build enrichment indexes
    proximity_idx = _build_proximity_index(attack_paths or [])
    disproven_idx = _build_disproven_index(disproven or [])
    hyp_idx = _build_hypothesis_index(hypotheses or [])

    lines = ["flowchart TD"]

    # Try to group into subgraphs
    groups = _find_subgraph_groups(nodes, root_id)

    if groups:
        # Root node first (outside subgraphs)
        if root_id and root_id in node_map:
            root_node = node_map[root_id]
            status = root_node.get("status", "unexplored")
            label = _node_label(root_node, proximity_idx, disproven_idx)
            open_ch, close_ch = _node_shape(status)
            lines.append(f"    {root_id}{open_ch}{label}{close_ch}")

        # Emit subgraph per top-level finding branch
        for group_id, desc_ids in groups.items():
            group_node = node_map.get(group_id, {})
            group_goal = _sanitize(group_node.get("goal", group_id))
            # Include proximity in subgraph label when available
            prox_suffix = ""
            if group_id in proximity_idx:
                score = proximity_idx[group_id]
                prox_suffix = f",proximity {score}/10"
            hyp_suffix = ""
            if group_id in hyp_idx:
                hyp_suffix = f",{hyp_idx[group_id]}"

            lines.append(f'    subgraph {group_id} ["{group_goal}{prox_suffix}{hyp_suffix}"]')

            # Group node itself
            status = group_node.get("status", "unexplored")
            label = _node_label(group_node, proximity_idx, disproven_idx)
            open_ch, close_ch = _node_shape(status)
            lines.append(f"        {group_id}{open_ch}{label}{close_ch}")

            # Descendants
            for did in desc_ids:
                dn = node_map.get(did)
                if not dn:
                    continue
                dstatus = dn.get("status", "unexplored")
                dlabel = _node_label(dn, proximity_idx, disproven_idx)
                dopen, dclose = _node_shape(dstatus)
                lines.append(f"        {did}{dopen}{dlabel}{dclose}")

            lines.append("    end")

        # Root → subgroup edges
        if root_id:
            for group_id in groups:
                lines.append(f"    {root_id} --> {group_id}")

        # Intra-subgraph edges
        lines.append("")
        lines.append("    %% Edges")
        all_subgraph_ids = {root_id} | set(groups.keys()) | {d for ds in groups.values() for d in ds}
        for node in nodes:
            if node.get("id") not in all_subgraph_ids:
                continue
            nid = node.get("id", "?")
            leads_to_raw = node.get("leads_to", "") or ""
            targets = [_sid(t.strip()) for t in leads_to_raw.split(",") if t.strip() and _sid(t.strip()) in node_map]
            for target in targets:
                if target != root_id:  # root edge already drawn above
                    lines.append(f"    {nid} --> {target}")

    else:
        # Flat rendering, original approach
        lines.append("")
        lines.append("    %% Nodes")
        for node in nodes:
            nid = node.get("id", "?")
            status = node.get("status", "unexplored")
            label = _node_label(node, proximity_idx, disproven_idx)
            open_ch, close_ch = _node_shape(status)
            lines.append(f"    {nid}{open_ch}{label}{close_ch}")

        lines.append("")
        lines.append("    %% Edges")
        for node in nodes:
            nid = node.get("id", "?")
            leads_to_raw = node.get("leads_to", "") or ""
            targets = [_sid(t.strip()) for t in leads_to_raw.split(",") if t.strip() and _sid(t.strip()) in node_map]
            for target in targets:
                lines.append(f"    {nid} --> {target}")

    # Style classes
    status_groups: dict[str, list[str]] = {}
    for node in nodes:
        s = _sanitize(node.get("status", "unexplored"))
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

    if root_id and root_id in node_map:
        lines.append(f"    style {root_id} stroke-width:3px")

    return "\n".join(lines)


def generate_from_file(
    path: Path,
    attack_paths_path: Path | None = None,
    disproven_path: Path | None = None,
    hypotheses_path: Path | None = None,
) -> str:
    data = load_json(path)
    if data is None:
        raise ValueError(f"Failed to load {path}")
    attack_paths = load_json(attack_paths_path) if attack_paths_path else None
    disproven_raw = load_json(disproven_path) if disproven_path else None
    disproven = disproven_raw.get("disproven", []) if isinstance(disproven_raw, dict) else disproven_raw
    hypotheses = load_json(hypotheses_path) if hypotheses_path else None
    return generate(data, attack_paths=attack_paths, disproven=disproven, hypotheses=hypotheses)
