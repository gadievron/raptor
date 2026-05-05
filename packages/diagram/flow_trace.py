"""
Mermaid diagram generator for flow-trace-*.json (produced by /understand --trace).

Renders each step in the data flow chain as a top-down flowchart node,
with branches shown as splits and sink nodes styled distinctly.
"""

from __future__ import annotations

from core.json import load_json
from pathlib import Path
from typing import Any

from .sanitize import sanitize as _sanitize, sanitize_id as _sid


def _step_label(step: dict[str, Any]) -> str:
    n = _sanitize(step.get("step", "?"))
    stype = _sanitize(str(step.get("type", "call")).upper())
    desc = _sanitize(step.get("description", ""))
    tainted = _sanitize(step.get("tainted_var", ""))
    loc = _sanitize(step.get("definition") or step.get("call_site") or "")
    confidence = _sanitize(step.get("confidence", ""))

    parts = [f"[{n}] {stype}"]
    if loc:
        parts.append(loc)
    if tainted:
        parts.append(f"tainted: {tainted}")
    if desc:
        # Truncate long descriptions
        short = desc if len(desc) <= 80 else desc[:77] + "..."
        parts.append(short)
    if confidence and confidence != "high":
        parts.append(f"confidence: {confidence}")
    return "\\n".join(parts)


def _parse_file_line(loc: str) -> tuple[str | None, int]:
    """Parse 'path/to/file.py:42' into ('path/to/file.py', 42).
    Returns (None, 0) if the string doesn't match the pattern."""
    if not loc:
        return None, 0
    parts = loc.rsplit(":", 1)
    if len(parts) == 2:
        try:
            return parts[0], int(parts[1])
        except ValueError:
            pass
    return None, 0


def _step_node_shape(step: dict[str, Any]) -> tuple[str, str]:
    """Return (open, close) Mermaid shape chars for a step type."""
    stype = step.get("type", "call")
    if stype == "entry":
        open_ch, close_ch = "([", "])"
        return open_ch, close_ch
    if stype == "sink":
        open_ch, close_ch = "[/", "\\]"
        return open_ch, close_ch
    if stype == "sanitize":
        return "{", "}"
    return "[", "]"


def _step_node_id(step: dict[str, Any], fallback: int | str = "?") -> str:
    """Return a safe Mermaid node ID for a flow-trace step."""
    return _sid(f"S{step.get('step', fallback)}")


def generate(data: dict[str, Any]) -> str:
    trace_id = data.get("id", "TRACE")
    name = _sanitize(data.get("name", trace_id))
    steps = data.get("steps", [])
    branches = data.get("branches", [])
    attacker_control = data.get("attacker_control") or {}


    if not steps:
        return f"flowchart TD\n    EMPTY[\"No steps in {trace_id}\"]"

    lines = ["flowchart TD"]
    lines.append(f'    TITLE["{name}"]')
    lines.append("    style TITLE fill:#f0f0f0,stroke:#999,font-weight:bold")
    lines.append("")

    node_ids: list[str] = ["TITLE"]

    for step in steps:
        nid = _step_node_id(step, len(node_ids))
        label = _step_label(step)
        open_ch, close_ch = _step_node_shape(step)
        lines.append(f'    {nid}{open_ch}"{label}"{close_ch}')
        node_ids.append(nid)

    # Main chain edges
    lines.append("")
    for i in range(len(node_ids) - 1):
        lines.append(f"    {node_ids[i]} --> {node_ids[i+1]}")

    # Branch annotations as separate note nodes
    if branches:
        lines.append("")
        lines.append("    %% Branches")
        for i, branch in enumerate(branches):
            bid = f"BR{i+1}"
            bp = _sanitize(branch.get("branch_point", ""))
            cond = _sanitize(branch.get("condition", ""))
            outcome = _sanitize(branch.get("outcome", ""))
            label = "\\n".join(filter(None, [f"Branch: {cond}", bp, outcome[:80] if outcome else ""]))
            lines.append(f'    {bid}[/"{label}"\\]')

            # Attach branch to the nearest step node that matches branch_point.
            # Strategy:
            #   1. Exact substring match (branch_point string appears in call_site or definition)
            #   2. File + closest-line match: parse file:line from branch_point and each
            #      step location; pick the step in the same file whose line is closest to
            #      (and does not exceed) the branch point line.
            #   3. Fall back to the first non-title step.
            branch_point_raw = branch.get("branch_point", "")
            attached = False

            # --- pass 1: exact substring ---
            for step in steps:
                call_site = step.get("call_site", "") or ""
                defn = step.get("definition", "") or ""
                if branch_point_raw and (branch_point_raw in call_site or branch_point_raw in defn):
                    lines.append(f"    {_step_node_id(step)} -. \"branch\" .-> {bid}")
                    attached = True
                    break

            # --- pass 2: file + nearest line ---
            if not attached and branch_point_raw:
                bp_file, bp_line = _parse_file_line(branch_point_raw)
                if bp_file is not None:
                    best_step = None
                    best_dist = float("inf")
                    for step in steps:
                        for loc in (step.get("call_site") or "", step.get("definition") or ""):
                            sf, sl = _parse_file_line(loc)
                            if sf is None:
                                continue
                            # Same file (suffix match handles relative vs absolute)
                            if not (sf.endswith(bp_file) or bp_file.endswith(sf)):
                                continue
                            # Prefer lines at or before the branch point; penalise lines after
                            dist = bp_line - sl if sl <= bp_line else (sl - bp_line) * 10
                            if dist < best_dist:
                                best_dist = dist
                                best_step = step
                    if best_step is not None:
                        lines.append(f"    {_step_node_id(best_step)} -. \"branch\" .-> {bid}")
                        attached = True

            # --- pass 3: attach to first real step ---
            if not attached and len(node_ids) > 1:
                lines.append(f"    {node_ids[1]} -. \"branch\" .-> {bid}")

    # Attacker control summary node
    level = _sanitize(str(attacker_control.get("level", "")).upper())
    what = _sanitize(attacker_control.get("what", ""))
    if level and what:
        lines.append("")
        ac_label = f"Attacker control: {level}\\n{what}"
        lines.append(f'    CTRL["{ac_label}"]')
        lines.append("    style CTRL fill:#fef9c3,stroke:#ca8a04")

    # Style: entry=blue, sink=red, call=default
    entry_ids = ",".join(_step_node_id(s) for s in steps if s.get("type") == "entry")
    sink_ids = ",".join(_step_node_id(s) for s in steps if s.get("type") == "sink")
    sanitize_ids = ",".join(_step_node_id(s) for s in steps if s.get("type") == "sanitize")

    lines.append("")
    lines.append("    classDef entry fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f")
    lines.append("    classDef sink fill:#fee2e2,stroke:#dc2626,color:#7f1d1d")
    lines.append("    classDef sanitize fill:#dcfce7,stroke:#16a34a,color:#14532d")
    if entry_ids:
        lines.append(f"    class {entry_ids} entry")
    if sink_ids:
        lines.append(f"    class {sink_ids} sink")
    if sanitize_ids:
        lines.append(f"    class {sanitize_ids} sanitize")

    return "\n".join(lines)


def generate_from_file(path: Path) -> str:
    data = load_json(path)
    if data is None:
        raise ValueError(f"Failed to load {path}")
    return generate(data)
