"""Mermaid renderers for graph-specific /understand memory artefacts."""

from __future__ import annotations

from typing import Any

from .sanitize import sanitize as _sanitize, sanitize_id as _sid


def generate_priority_paths(paths: list[dict[str, Any]], *, limit: int = 20) -> str:
    """Render graph-priority-paths.json as a compact risk flowchart."""
    lines = ["flowchart LR"]
    if not paths:
        lines.append('    EMPTY["No graph-priority paths"]')
        return "\n".join(lines)

    lines.append("")
    lines.append("    %% Graph-derived source-to-sink paths")
    for i, path in enumerate(paths[:limit]):
        pid = _sid(path.get("id") or f"GRAPH-PATH-{i + 1}")
        entry = path.get("entry") if isinstance(path.get("entry"), dict) else {}
        sink = path.get("sink") if isinstance(path.get("sink"), dict) else {}
        entry_label = _node_label(entry, fallback="entry")
        sink_label = _node_label(sink, fallback="sink")
        risk = path.get("risk_score")
        confidence = path.get("confidence") or path.get("evidence", {}).get("confidence") or "candidate"
        missing = path.get("missing_boundary") or "graph path"

        entry_id = f"{pid}_ENTRY"
        sink_id = f"{pid}_SINK"
        lines.append(f'    {entry_id}["{_sanitize(entry_label)}"]')
        lines.append(f'    {sink_id}[/"{_sanitize(sink_label)}"\\]')

        edge = f"{confidence}"
        if risk is not None:
            edge += f", risk {risk}"
        lines.append(f'    {entry_id} -. "{_sanitize(edge)}" .-> {sink_id}')

        if missing:
            note_id = f"{pid}_NOTE"
            lines.append(f'    {note_id}["{_sanitize(str(missing), max_len=120)}"]')
            lines.append(f"    {entry_id} -. missing boundary .-> {note_id}")
            lines.append(f"    {note_id} -.-> {sink_id}")

    if len(paths) > limit:
        lines.append("")
        lines.append(f'    MORE["{len(paths) - limit} more graph paths not shown"]')

    lines.extend([
        "",
        "    classDef entry fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f",
        "    classDef sink fill:#fee2e2,stroke:#dc2626,color:#7f1d1d",
        "    classDef note fill:#fef9c3,stroke:#ca8a04,color:#713f12",
    ])
    entry_ids = ",".join(f"{_sid(p.get('id') or f'GRAPH-PATH-{i + 1}')}_ENTRY" for i, p in enumerate(paths[:limit]))
    sink_ids = ",".join(f"{_sid(p.get('id') or f'GRAPH-PATH-{i + 1}')}_SINK" for i, p in enumerate(paths[:limit]))
    note_ids = ",".join(f"{_sid(p.get('id') or f'GRAPH-PATH-{i + 1}')}_NOTE" for i, p in enumerate(paths[:limit]) if p.get("missing_boundary"))
    if entry_ids:
        lines.append(f"    class {entry_ids} entry")
    if sink_ids:
        lines.append(f"    class {sink_ids} sink")
    if note_ids:
        lines.append(f"    class {note_ids} note")
    return "\n".join(lines)


def generate_diff(diff: dict[str, Any]) -> str:
    """Render graph diff JSON from raptor-graph-query --diff."""
    lines = ["flowchart TD"]
    if not diff or diff.get("is_diffable") is False:
        reason = diff.get("reason") if isinstance(diff, dict) else "no diff data"
        lines.append(f'    EMPTY["{_sanitize(reason or "No graph diff available")}"]')
        return "\n".join(lines)

    base = diff.get("base_snapshot", {}) if isinstance(diff.get("base_snapshot"), dict) else {}
    head = diff.get("head_snapshot", {}) if isinstance(diff.get("head_snapshot"), dict) else {}
    lines.append(
        f'    BASE["Base\\n{_sanitize(base.get("id") or "snapshot")}"] --> HEAD["Head\\n{_sanitize(head.get("id") or "snapshot")}"]'
    )

    added_risks = diff.get("new_risks") or []
    added_reachability = (diff.get("reachability") or {}).get("added") or []
    removed_reachability = (diff.get("reachability") or {}).get("removed") or []

    for i, edge in enumerate(added_risks[:12]):
        nid = f"RISK{i:03d}"
        label = _diff_edge_label(edge, prefix="New risk")
        lines.append(f'    {nid}["{_sanitize(label, max_len=140)}"]')
        lines.append(f"    HEAD --> {nid}")

    for i, edge in enumerate(added_reachability[:12]):
        nid = f"ADD{i:03d}"
        if any(_same_edge(edge, risk) for risk in added_risks):
            continue
        label = _diff_edge_label(edge, prefix="Added path")
        lines.append(f'    {nid}["{_sanitize(label, max_len=140)}"]')
        lines.append(f"    HEAD --> {nid}")

    for i, edge in enumerate(removed_reachability[:12]):
        nid = f"REM{i:03d}"
        label = _diff_edge_label(edge, prefix="Removed path")
        lines.append(f'    {nid}["{_sanitize(label, max_len=140)}"]')
        lines.append(f"    BASE -.-> {nid}")

    node_sections = diff.get("nodes") if isinstance(diff.get("nodes"), dict) else {}
    for kind, change in node_sections.items():
        if not isinstance(change, dict):
            continue
        added = change.get("added") or []
        removed = change.get("removed") or []
        if not added and not removed:
            continue
        group_id = _sid(f"NODE_{kind}")
        lines.append(f'    {group_id}["{_sanitize(kind)}: +{len(added)} / -{len(removed)}"]')
        lines.append(f"    HEAD --> {group_id}")

    lines.extend([
        "",
        "    classDef risk fill:#fee2e2,stroke:#dc2626,color:#7f1d1d",
        "    classDef added fill:#dcfce7,stroke:#16a34a,color:#14532d",
        "    classDef removed fill:#f3f4f6,stroke:#6b7280,color:#111827",
        "    classDef snap fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f",
        "    class BASE,HEAD snap",
    ])
    risk_ids = ",".join(f"RISK{i:03d}" for i in range(min(len(added_risks), 12)))
    if risk_ids:
        lines.append(f"    class {risk_ids} risk")
    return "\n".join(lines)


def _node_label(node: dict[str, Any], *, fallback: str) -> str:
    label = node.get("label") or node.get("name") or node.get("id") or fallback
    location = node.get("location")
    if location:
        return f"{label}\\n{location}"
    return str(label)


def _diff_edge_label(edge: dict[str, Any], *, prefix: str) -> str:
    source = edge.get("source") or edge.get("source_file") or "source"
    sink = edge.get("sink") or edge.get("sink_file") or "sink"
    confidence = edge.get("confidence") or "candidate"
    return f"{prefix}: {source} -> {sink} ({confidence})"


def _same_edge(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        left.get("source") == right.get("source")
        and left.get("sink") == right.get("sink")
        and left.get("source_file") == right.get("source_file")
        and left.get("sink_file") == right.get("sink_file")
    )
