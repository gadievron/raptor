"""
Mermaid diagram generator for attack-paths.json (produced by /validate Stage B).

Each attack path becomes its own flowchart showing the step chain,
proximity score, and any blockers. WIP: we may want to add more details, e.g. showing which steps are confirmed vs theoretical, or adding more info about blockers.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from core.json import load_json
from core.security.markdown_render import md_inline

from .caps import cap_elements, truncation_marker_lines
from .envelope import unwrap_list
from .sanitize import sanitize as _sanitize

if TYPE_CHECKING:
    from pathlib import Path

# Per-path element caps (shared flow_trace rationale: unbounded
# LLM/run artifacts hang browsers, trip Mermaid's complexity limit
# and blow markdown size budgets). Steps use the shared 200; blockers
# are annotation nodes hanging off the last step, useless past a
# screenful — 50 keeps the worst case readable while no legitimate
# path observed carries more than a handful.
_MAX_STEPS = 200
_MAX_BLOCKERS = 50

# Markdown-level caps: each path is a WHOLE diagram section, so the
# per-element cap is much lower than the in-diagram one. The byte
# budget mirrors the renderer's _fence budget (200k) — this generator
# emits its own ```mermaid fences and is appended to diagrams.md RAW
# (self-fenced blocks skip the renderer's last-hop _fence), so the
# budget must live here or nowhere. Lower values would cut legitimate
# multi-path reports sooner; higher values re-open the oversize
# report failure the fence budget exists to stop.
_MAX_PATHS = 50
_MAX_SECTION_BYTES = 200_000

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


def generate_single(path_data: dict[str, Any], path_index: int) -> str:
    """Generate Mermaid for a single attack path."""
    path_id = path_data.get("id", f"PATH-{path_index+1}")
    name = _sanitize(path_data.get("name", path_id))
    steps = path_data.get("steps", [])
    if not isinstance(steps, list):
        steps = []
    steps, truncated_steps = cap_elements(steps, _MAX_STEPS)
    proximity = path_data.get("proximity") or 0
    blockers = path_data.get("blockers", [])
    if not isinstance(blockers, list):
        blockers = []
    blockers, truncated_blockers = cap_elements(blockers, _MAX_BLOCKERS)
    status = _sanitize(str(path_data.get("status", "uncertain")))

    try:
        proximity = int(proximity)
    except (TypeError, ValueError):
        proximity = 0
    prox_desc = _proximity_desc(proximity)
    has_runtime = path_data.get("runtime_evidence_available", False)

    lines = ["flowchart TD"]
    rt_tag = " [Runtime Confirmed]" if has_runtime else ""
    # Each raw part (name, status) is sanitized exactly once at
    # extraction above. _sanitize is not idempotent ('&' → '&amp;' →
    # '&amp;amp;'), so re-sanitizing the assembled label mangled any
    # name containing &, < or > in the rendered title.
    title_label = f"{name}{rt_tag}\\nProximity: {proximity}/10 — {prox_desc}\\nStatus: {status}"
    lines.append(f'    TITLE_{path_index}["{title_label}"]')
    lines.append(f"    style TITLE_{path_index} fill:#f0f0f0,stroke:#999,font-weight:bold")
    lines.append("")

    node_ids = [f"TITLE_{path_index}"]

    runtime_nodes = []

    for i, step in enumerate(steps):
        nid = f"P{path_index}S{i+1}"
        # Steps may be objects or strings
        if isinstance(step, dict):
            step_type = _sanitize(str(step.get("type", "call")).upper())
            # `or`-chained so an explicit null description doesn't
            # render the literal text 'None'; the whole-dict fallback
            # only applies when neither key exists at all.
            desc_raw = step.get("description") or step.get("action")
            if desc_raw is None and "description" not in step \
                    and "action" not in step:
                desc_raw = str(step)
            desc = _sanitize(desc_raw) if desc_raw else ""
            loc = _sanitize(step.get("call_site") or step.get("definition") or "")
            tainted = _sanitize(step.get("tainted_var") or "")
            # The step's outcome is the value-level evidence an
            # operator judges exploitability by ('sent 24 bytes' means
            # little without 'RIP=0x41414141') — render it.
            outcome = _sanitize(step.get("result") or "")
            # runtime_evidence comes raw from attack-paths.json; a
            # non-dict value (string, list, null) would crash the
            # whole section on the .get() calls below — coerce like
            # the call_count / proximity handling.
            rt_ev = step.get("runtime_evidence")
            if not isinstance(rt_ev, dict):
                rt_ev = {}
            parts = [f"[{i+1}] {step_type}"]
            if loc:
                parts.append(loc)
            if tainted:
                parts.append(f"tainted: {tainted}")
            if desc:
                short = desc if len(desc) <= 80 else desc[:77] + "..."
                parts.append(short)
            if outcome:
                short_outcome = (
                    outcome if len(outcome) <= 80 else outcome[:77] + "..."
                )
                parts.append(f"result: {short_outcome}")
            if rt_ev.get("function_observed"):
                # call_count comes raw from runtime-evidence JSON; coerce to
                # int so a non-numeric value can't reach the Mermaid label.
                try:
                    count = int(rt_ev.get("call_count", 0))
                except (TypeError, ValueError):
                    count = 0
                parts.append(f"Observed x{count}")
                runtime_nodes.append(nid)
            label = "\\n".join(parts)
        else:
            label = _sanitize(f"[{i+1}] {step!s}")

        lines.append(f'    {nid}["{label}"]')
        node_ids.append(nid)

    # Style runtime-confirmed steps
    if runtime_nodes:
        lines.append("")
        lines.append("    %% Runtime-confirmed (frida)")
        lines.extend(f"    style {nid} fill:#dbeafe,stroke:#2563eb,stroke-width:2px" for nid in runtime_nodes)

    # Chain edges
    lines.append("")
    lines.extend(f"    {node_ids[i]} --> {node_ids[i+1]}" for i in range(len(node_ids) - 1))

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

    lines.extend(truncation_marker_lines(
        f"TRUNC_{path_index}", truncated_steps, "steps", _MAX_STEPS))
    lines.extend(truncation_marker_lines(
        f"TRUNCBLK_{path_index}", truncated_blockers, "blockers",
        _MAX_BLOCKERS))

    return "\n".join(lines)


def generate(data: list[dict[str, Any]]) -> str:
    """Generate one Mermaid diagram per path, returned as combined markdown."""
    if not data:
        return '```mermaid\nflowchart TD\n    EMPTY["No attack paths"]\n```'

    paths, dropped = cap_elements(data, _MAX_PATHS)

    sections: list[str] = []
    total_bytes = 0
    for i, path_data in enumerate(paths):
        # id/name/status come raw from attack-paths.json; sanitize so a
        # crafted value can't break the heading out of its line.
        raw_id = path_data.get("id", f"PATH-{i+1}")
        path_id = _sanitize(raw_id)
        name = _sanitize(path_data.get("name", raw_id))
        try:
            proximity = int(path_data.get("proximity") or 0)
        except (TypeError, ValueError):
            proximity = 0
        status = _sanitize(path_data.get("status", "uncertain"))
        # The heading is a MARKDOWN line: after the Mermaid label
        # sanitize, md_inline handles the heading's own context
        # (backticks, image-autofetch markup — both live in markdown,
        # both left alone by the label sanitizer).
        heading = md_inline(
            f"{path_id}: {name} (Proximity {proximity}/10, {status})",
        )
        block = "\n".join((
            f"#### {heading}\n",
            "```mermaid",
            generate_single(path_data, i),
            "```\n",
        ))
        # Byte budget on the assembled markdown: whole blocks only, so
        # truncation can never land mid-fence and spill live markdown.
        if sections and total_bytes + len(block) > _MAX_SECTION_BYTES:
            dropped += len(paths) - i
            break
        sections.append(block)
        total_bytes += len(block)

    if dropped:
        sections.append(
            f"> ⚠ Attack-paths section truncated: {dropped} of "
            f"{len(data)} path(s) not shown (path cap {_MAX_PATHS}, "
            f"section budget {_MAX_SECTION_BYTES} bytes).\n",
        )

    return "\n".join(sections)


def generate_from_file(path: Path) -> str:
    data = load_json(path)
    if data is None:
        msg = f"Failed to load {path}"
        raise ValueError(msg)
    return generate(unwrap_list(data, keys=("paths", "attack_paths")) or [])
