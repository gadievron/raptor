"""
Mermaid diagram generator for attack-paths.json (produced by /validate Stage B).

Each attack path becomes its own flowchart showing the step chain,
proximity score, and any blockers. WIP: we may want to add more details, e.g. showing which steps are confirmed vs theoretical, or adding more info about blockers.
"""

from __future__ import annotations

from core.json import load_json
from pathlib import Path
from typing import Any

from .sanitize import sanitize as _sanitize


_PROXIMITY_LABEL = {
    (0, 1): "Theoretical only",
    (2, 3): "Flow confirmed, blocked",
    (4, 5): "Reachable, partial bypass",
    (6, 7): "Exploit primitive confirmed",
    (8, 9): "Working PoC",
    (10, 10): "Reliable exploitation",
}


def _proximity_desc(score: int) -> str:
    for (lo, hi), label in _PROXIMITY_LABEL.items():
        if lo <= score <= hi:
            return label
    return "Unknown"


def _path_status_style(status: str) -> str:
    if status == "confirmed":
        return "fill:#dcfce7,stroke:#16a34a"
    if status == "blocked":
        return "fill:#fee2e2,stroke:#dc2626"
    return "fill:#fef9c3,stroke:#ca8a04"


def generate_single(path_data: dict[str, Any], path_index: int) -> str:
    """Generate Mermaid for a single attack path."""
    path_id = path_data.get("id", f"PATH-{path_index+1}")
    name = _sanitize(path_data.get("name", path_id))
    steps = path_data.get("steps", [])
    proximity = path_data.get("proximity", 0)
    blockers = path_data.get("blockers", [])
    status = path_data.get("status", "uncertain")

    prox_desc = _proximity_desc(int(proximity))

    lines = ["flowchart TD"]
    title_label = f"{name}\\nProximity: {proximity}/10,{prox_desc}\\nStatus: {status}"
    lines.append(f'    TITLE_{path_index}["{_sanitize(title_label)}"]')
    lines.append(f"    style TITLE_{path_index} fill:#f0f0f0,stroke:#999,font-weight:bold")
    lines.append("")

    node_ids = [f"TITLE_{path_index}"]

    for i, step in enumerate(steps):
        nid = f"P{path_index}S{i+1}"
        # Steps may be objects or strings
        if isinstance(step, dict):
            step_type = _sanitize(str(step.get("type", "call")).upper())
            desc = _sanitize(step.get("description", step.get("action", str(step))))
            loc = _sanitize(step.get("call_site") or step.get("definition") or "")
            tainted = _sanitize(step.get("tainted_var", ""))
            parts = [f"[{i+1}] {step_type}"]
            if loc:
                parts.append(loc)
            if tainted:
                parts.append(f"tainted: {tainted}")
            if desc:
                short = desc if len(desc) <= 80 else desc[:77] + "..."
                parts.append(short)
            label = "\\n".join(parts)
        else:
            label = _sanitize(f"[{i+1}] {str(step)}")

        lines.append(f'    {nid}["{label}"]')
        node_ids.append(nid)

    # Chain edges
    lines.append("")
    for i in range(len(node_ids) - 1):
        lines.append(f"    {node_ids[i]} --> {node_ids[i+1]}")

    # Blocker nodes
    if blockers:
        lines.append("")
        lines.append("    %% Blockers")
        for j, blocker in enumerate(blockers):
            bid = f"BLK{path_index}_{j+1}"
            blocker_text = _sanitize(str(blocker) if not isinstance(blocker, dict) else
                                     blocker.get("description", blocker.get("reason", str(blocker))))
            lines.append(f'    {bid}[/"Blocker: {blocker_text}"\\]')
            lines.append(f"    style {bid} fill:#fee2e2,stroke:#dc2626,color:#7f1d1d")
            # Attach to last step
            if node_ids:
                lines.append(f"    {node_ids[-1]} -. \"blocked\" .-> {bid}")

    return "\n".join(lines)


def generate(data: list[dict[str, Any]]) -> str:
    """Generate one Mermaid diagram per path, returned as combined markdown."""
    if not data:
        return '```mermaid\nflowchart TD\n    EMPTY["No attack paths"]\n```'

    sections = []
    for i, path_data in enumerate(data):
        path_id = path_data.get("id", f"PATH-{i+1}")
        name = path_data.get("name", path_id)
        proximity = path_data.get("proximity", 0)
        status = path_data.get("status", "uncertain")
        sections.append(f"#### {path_id}: {name} (Proximity {proximity}/10, {status})\n")
        sections.append("```mermaid")
        sections.append(generate_single(path_data, i))
        sections.append("```\n")

    return "\n".join(sections)


def generate_from_file(path: Path) -> str:
    data = load_json(path)
    if data is None:
        raise ValueError(f"Failed to load {path}")
    if isinstance(data, dict):
        # Some files wrap array in a key
        data = data.get("paths", data.get("attack_paths", list(data.values())[0] if data else []))
    return generate(data if isinstance(data, list) else [])
