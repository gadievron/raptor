"""
Diagram renderer: discovers JSON outputs in an /understand or /validate output
directory and produces a consolidated diagrams.md with all Mermaid charts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import context_map, flow_trace, attack_tree, attack_paths


# Files we know how to render, in display order
_KNOWN_FILES = [
    "context-map.json",
    "attack-surface.json",
    "attack-tree.json",
    "attack-paths.json",
]

# flow-trace files are discovered by glob
_FLOW_TRACE_GLOB = "flow-trace-*.json"


def _section(title: str, body: str, level: int = 2) -> str:
    heading = "#" * level
    return f"{heading} {title}\n\n{body}\n"


def render_directory(out_dir: Path, target: Optional[str] = None) -> str:
    """
    Discover all known JSON outputs in out_dir and render a combined diagrams.md.
    Returns the markdown string.
    """
    out_dir = Path(out_dir)
    sections: list[str] = []

    # Header
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    target_str = f" for `{target}`" if target else ""
    sections.append(f"# Security Diagrams{target_str}\n\n_Generated {now}_\n")

    # --- Context map / attack surface ---
    for fname, title in [
        ("context-map.json", "Context Map — Entry Points, Trust Boundaries, Sinks"),
        ("attack-surface.json", "Attack Surface (Stage B)"),
    ]:
        fpath = out_dir / fname
        if not fpath.exists():
            continue
        try:
            data = json.loads(fpath.read_text())
            diagram = context_map.generate(data)
            body = f"_Source: `{fname}`_\n\n```mermaid\n{diagram}\n```"
            sections.append(_section(title, body))
        except Exception as exc:
            sections.append(_section(title, f"> Could not render `{fname}`: {exc}"))

    # --- Flow traces ---
    trace_files = sorted(out_dir.glob(_FLOW_TRACE_GLOB))
    if trace_files:
        trace_sections: list[str] = []
        for tf in trace_files:
            try:
                data = json.loads(tf.read_text())
                trace_id = data.get("id", tf.stem)
                name = data.get("name", trace_id)
                diagram = flow_trace.generate(data)
                body = f"_Source: `{tf.name}`_\n\n```mermaid\n{diagram}\n```"
                trace_sections.append(_section(f"{trace_id}: {name}", body, level=3))
            except Exception as exc:
                trace_sections.append(_section(tf.stem, f"> Could not render `{tf.name}`: {exc}", level=3))
        sections.append(_section("Data Flow Traces", "\n".join(trace_sections)))

    # --- Attack tree ---
    tree_path = out_dir / "attack-tree.json"
    if tree_path.exists():
        try:
            data = json.loads(tree_path.read_text())
            diagram = attack_tree.generate(data)
            body = f"_Source: `attack-tree.json`_\n\n```mermaid\n{diagram}\n```"
            sections.append(_section("Attack Tree", body))
        except Exception as exc:
            sections.append(_section("Attack Tree", f"> Could not render `attack-tree.json`: {exc}"))

    # --- Attack paths ---
    paths_path = out_dir / "attack-paths.json"
    if paths_path.exists():
        try:
            data = json.loads(paths_path.read_text())
            if isinstance(data, dict):
                data = (data.get("paths") or data.get("attack_paths") or
                        next(iter(data.values()), []))
            if isinstance(data, list) and data:
                body = f"_Source: `attack-paths.json`_\n\n" + attack_paths.generate(data)
                sections.append(_section("Attack Paths", body))
        except Exception as exc:
            sections.append(_section("Attack Paths", f"> Could not render `attack-paths.json`: {exc}"))

    if len(sections) <= 1:
        sections.append("> No renderable JSON outputs found in this directory.\n")

    return "\n".join(sections)


def render_and_write(out_dir: Path, target: Optional[str] = None) -> Path:
    """
    Render all diagrams and write diagrams.md into out_dir.
    Returns the path to the written file.
    """
    content = render_directory(out_dir, target)
    output_path = out_dir / "diagrams.md"
    output_path.write_text(content, encoding="utf-8")
    return output_path
