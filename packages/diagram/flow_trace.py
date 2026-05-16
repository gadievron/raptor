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
    Returns (None, 0) if the string doesn't match the pattern.

    Validate path-shape on the file portion. Pre-fix
    `parts[0]` was returned without checking — input like
    `:42` (empty path), `   :42` (whitespace path), or
    `a:b:c:42` (after `rsplit(":", 1)` the path part still
    contains `:`) was returned as a "file path" that
    downstream consumers (file matching, branch attachment)
    couldn't sensibly compare against real step file paths,
    causing matching to silently miss legitimate
    correspondences.
    """
    if not loc:
        return None, 0
    parts = loc.rsplit(":", 1)
    if len(parts) == 2:
        try:
            line_num = int(parts[1])
        except ValueError:
            return None, 0
        file_part = parts[0].strip()
        # Reject empty / whitespace-only / clearly-non-path
        # results. A legitimate path can contain `:` (Windows
        # drive letters, time-prefixed log lines that someone
        # mistakenly passed through here), so we don't reject
        # those — we just require non-empty after strip.
        if not file_part:
            return None, 0
        return file_part, line_num
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
    # Cap step count. Pre-fix `steps` was used unbounded;
    # legitimate large traces (deep call chains in
    # generated code, recursive analyses) produced
    # massive Mermaid diagrams that:
    #   * Took 10+ seconds to render in browsers, blocking
    #     the operator UI thread.
    #   * Hit Mermaid's own internal node-count limits and
    #     produced cryptic "diagram too complex" errors.
    #   * Exceeded markdown-rendering tools' size budgets,
    #     causing reports to silently truncate at the
    #     wrong place.
    # 200 steps is the largest size that renders cleanly in
    # mainstream Mermaid setups. Cap with a clear annotation
    # in the diagram so the operator knows WHY truncation
    # happened.
    _MAX_STEPS = 200
    truncated_count = 0
    if len(steps) > _MAX_STEPS:
        truncated_count = len(steps) - _MAX_STEPS
        steps = steps[:_MAX_STEPS]
    branches = data.get("branches", [])
    attacker_control = data.get("attacker_control") or {}


    if not steps:
        return f"flowchart TD\n    EMPTY[\"No steps in {trace_id}\"]"

    lines = ["flowchart TD"]
    lines.append(f'    TITLE["{name}"]')
    lines.append("    style TITLE fill:#f0f0f0,stroke:#999,font-weight:bold")
    lines.append("")

    node_ids: list[str] = ["TITLE"]
    # Stable per-step ID map so subsequent _step_node_id calls
    # (branch attachment, class-list assembly) reuse the SAME id
    # this loop assigned. Pre-fix the later call sites used the
    # default `fallback="?"`, so when two steps both lacked an
    # explicit `step` field, BOTH got id "S?" — Mermaid collapsed
    # them into one graphical node, losing the visual
    # distinction between them. Keying by `id(step)` gives a
    # process-stable handle that's unique per step object
    # within this call's `steps` list.
    step_id_map: dict[int, str] = {}

    for step in steps:
        nid = _step_node_id(step, len(node_ids))
        # Disambiguate when the per-step `step` field is missing
        # or duplicated across multiple steps. Suffix with the
        # 1-based index ensures every step gets a unique node
        # id even if `step` field collides.
        if nid in node_ids:
            nid = f"{nid}_{len(node_ids)}"
        step_id_map[id(step)] = nid
        label = _step_label(step)
        open_ch, close_ch = _step_node_shape(step)
        lines.append(f'    {nid}{open_ch}"{label}"{close_ch}')
        node_ids.append(nid)

    def _stable_id(step: dict[str, Any]) -> str:
        """Return the id this loop assigned, falling back to
        derivation for callers that pass a step dict not in
        `steps` (defensive — shouldn't happen, but the fallback
        keeps us correctness-equivalent to pre-fix in that
        edge case)."""
        return step_id_map.get(id(step), _step_node_id(step))

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
                    lines.append(f"    {_stable_id(step)} -. \"branch\" .-> {bid}")
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
                        lines.append(f"    {_stable_id(best_step)} -. \"branch\" .-> {bid}")
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
    entry_ids = ",".join(_stable_id(s) for s in steps if s.get("type") == "entry")
    sink_ids = ",".join(_stable_id(s) for s in steps if s.get("type") == "sink")
    sanitize_ids = ",".join(_stable_id(s) for s in steps if s.get("type") == "sanitize")

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

    if truncated_count > 0:
        lines.append("")
        lines.append(
            f'    TRUNC["⚠ Diagram truncated: '
            f'{truncated_count} additional steps not shown '
            f'(cap {_MAX_STEPS})"]'
        )
        lines.append("    style TRUNC fill:#fef9c3,stroke:#a16207")

    return "\n".join(lines)


def generate_from_file(path: Path) -> str:
    data = load_json(path)
    if data is None:
        raise ValueError(f"Failed to load {path}")
    return generate(data)
