"""
Mermaid diagram generator for context-map.json (produced by /understand --map).

Renders entry points → trust boundaries → sinks as a left-to-right flowchart,
with unchecked flows shown as dashed edges.
"""

from __future__ import annotations

from core.json import load_json
from pathlib import Path
from typing import Any

from .sanitize import sanitize as _sanitize, sanitize_id as _sid


def _node_id(prefix: str, index: int) -> str:
    return f"{prefix}{index:03d}"


def generate(data: dict[str, Any]) -> str:
    """Return Mermaid flowchart markdown from a context-map.json dict."""
    lines = ["flowchart LR"]

    entry_points = data.get("entry_points", [])
    boundary_details = data.get("boundary_details", [])
    sink_details = data.get("sink_details", [])
    unchecked_flows = data.get("unchecked_flows", [])

    # Fallback: plain sources/sinks when detailed lists are absent
    if not entry_points and data.get("sources"):
        entry_points = [
            {"id": f"EP-{i+1:03d}", "type": s.get("type", "source"),
             "path": s.get("entry") or s.get("description") or s.get("name") or "unknown",
             "file": "", "line": ""}
            for i, s in enumerate(data["sources"])
        ]
    if not sink_details and data.get("sinks"):
        sink_details = [
            {"id": f"SINK-{i+1:03d}", "type": s.get("type", "sink"),
             "operation": s.get("location") or s.get("description") or s.get("name") or "unknown",
             "file": "", "line": ""}
            for i, s in enumerate(data["sinks"])
        ]

    # -- Entry point nodes --
    if entry_points:
        lines.append("")
        lines.append("    %% Entry Points")
    for ep in entry_points:
        ep_id = _sid(ep.get("id", "EP-?"))
        method = ep.get("method", "")
        path = ep.get("path", ep.get("entry", "?"))
        file_ref = ep.get("file", "")
        line_ref = ep.get("line", "")
        loc = f"{file_ref}:{line_ref}" if file_ref else ""
        auth = "" if ep.get("auth_required", True) else " [PUBLIC]"
        label = _sanitize(f"{method} {path}{auth}\\n{loc}".strip())
        lines.append(f'    {ep_id}["{label}"]')

    # -- Trust boundary nodes --
    if boundary_details:
        lines.append("")
        lines.append("    %% Trust Boundaries")
    for tb in boundary_details:
        tb_id = _sid(tb.get("id", "TB-?"))
        boundary = _sanitize(tb.get("boundary", tb.get("type", "?")))
        file_ref = tb.get("file", "")
        line_ref = tb.get("line", "")
        loc = f"{file_ref}:{line_ref}" if file_ref else ""
        label = _sanitize(f"{boundary}\\n{loc}".strip())
        lines.append(f'    {tb_id}{{"{label}"}}')

    # -- Sink nodes --
    if sink_details:
        lines.append("")
        lines.append("    %% Sinks")
    for sink in sink_details:
        sink_id = _sid(sink.get("id", "SINK-?"))
        op = sink.get("operation", sink.get("type", "?"))
        file_ref = sink.get("file", "")
        line_ref = sink.get("line", "")
        loc = f"{file_ref}:{line_ref}" if file_ref else ""
        label = _sanitize(f"{op}\\n{loc}".strip())
        lines.append(f'    {sink_id}[/"{label}"\\]')

    # -- Edges: EP → TB (covers) --
    lines.append("")
    lines.append("    %% Flows")
    covered_eps: set[str] = set()
    for tb in boundary_details:
        tb_id = _sid(tb.get("id", "TB-?"))
        for ep_id in [_sid(e) for e in tb.get("covers", [])]:
            lines.append(f"    {ep_id} --> {tb_id}")
            covered_eps.add(ep_id)

    # -- Edges: TB → SINK (reaches_from) --
    for sink in sink_details:
        sink_id = _sid(sink.get("id", "SINK-?"))
        for ep_id in [_sid(e) for e in sink.get("reaches_from", [])]:
            # Find which TB covers this EP
            tb_for_ep = [
                _sid(tb.get("id")) for tb in boundary_details
                if ep_id in [_sid(e) for e in tb.get("covers", [])]
            ]
            if tb_for_ep:
                for tb_id in tb_for_ep:
                    lines.append(f"    {tb_id} --> {sink_id}")
            else:
                # No TB, direct edge (will also appear as unchecked)
                lines.append(f"    {ep_id} --> {sink_id}")

    # -- Unchecked flows: dashed red edges --
    if unchecked_flows:
        lines.append("")
        lines.append("    %% Unchecked Flows (no trust boundary)")
    for flow in unchecked_flows:
        ep_id = _sid(flow.get("entry_point", "?"))
        sink_id = _sid(flow.get("sink", "?"))
        reason = _sanitize(flow.get("missing_boundary", "no check"))
        lines.append(f"    {ep_id} -. \"{reason}\" .-> {sink_id}")

    # -- Style classes --
    lines.append("")
    lines.append("    classDef ep fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f")
    lines.append("    classDef tb fill:#fef9c3,stroke:#ca8a04,color:#713f12")
    lines.append("    classDef sink fill:#fee2e2,stroke:#dc2626,color:#7f1d1d")

    if entry_points:
        ep_ids = ",".join(_sid(ep.get("id", "")) for ep in entry_points)
        lines.append(f"    class {ep_ids} ep")
    if boundary_details:
        tb_ids = ",".join(_sid(tb.get("id", "")) for tb in boundary_details)
        lines.append(f"    class {tb_ids} tb")
    if sink_details:
        sink_ids = ",".join(_sid(s.get("id", "")) for s in sink_details)
        lines.append(f"    class {sink_ids} sink")

    return "\n".join(lines)


def generate_from_file(path: Path) -> str:
    data = load_json(path)
    if data is None:
        raise ValueError(f"Failed to load {path}")
    return generate(data)
