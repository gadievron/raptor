"""
Diagram renderer: discovers JSON outputs in an /understand or /validate output
directory and produces a consolidated diagrams.md with all Mermaid charts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from core.json import load_json as _load_json

from . import context_map, flow_trace, attack_tree, attack_paths, hypotheses


_FLOW_TRACE_GLOB = "flow-trace-*.json"


def _section(title: str, body: str, level: int = 2) -> str:
    heading = "#" * level
    return f"{heading} {title}\n\n{body}\n"


def render_directory(out_dir: Path, target: Optional[str] = None) -> str:
    out_dir = Path(out_dir)
    sections: list[str] = []

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    target_str = f" for `{target}`" if target else ""
    sections.append(f"# Security Diagrams{target_str}\n\n_Generated {now}_\n")

    # --- Context map / attack surface ---
    for fname, title in [
        ("context-map.json", "Context Map, Entry Points, Trust Boundaries, Sinks"),
        ("attack-surface.json", "Attack Surface (Stage B)"),
    ]:
        fpath = out_dir / fname
        if not fpath.exists():
            continue
        try:
            data = _load_json(fpath)
            if data is None:
                raise ValueError("failed to parse JSON")
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
                data = _load_json(tf)
                if data is None:
                    raise ValueError("failed to parse JSON")
                trace_id = data.get("id", tf.stem)
                name = data.get("name", trace_id)
                diagram = flow_trace.generate(data)
                body = f"_Source: `{tf.name}`_\n\n```mermaid\n{diagram}\n```"
                trace_sections.append(_section(f"{trace_id}: {name}", body, level=3))
            except Exception as exc:
                trace_sections.append(_section(tf.stem, f"> Could not render `{tf.name}`: {exc}", level=3))
        sections.append(_section("Data Flow Traces", "\n".join(trace_sections)))

    # --- Attack tree (with companion files for enrichment) ---
    tree_path = out_dir / "attack-tree.json"
    if tree_path.exists():
        try:
            data = _load_json(tree_path)
            if data is None:
                raise ValueError("failed to parse JSON")

            # Load companion files for cross-referencing
            ap_data = _load_optional_list(out_dir / "attack-paths.json")
            disproven_data = _load_disproven(out_dir / "disproven.json")
            hyp_data = _load_optional_list(out_dir / "hypotheses.json")

            enriched = any([ap_data, disproven_data, hyp_data])
            note = " _(enriched with proximity scores and disproven reasons)_" if enriched else ""

            diagram = attack_tree.generate(
                data,
                attack_paths=ap_data,
                disproven=disproven_data,
                hypotheses=hyp_data,
            )
            body = f"_Source: `attack-tree.json`_{note}\n\n```mermaid\n{diagram}\n```"
            sections.append(_section("Attack Tree", body))
        except Exception as exc:
            sections.append(_section("Attack Tree", f"> Could not render `attack-tree.json`: {exc}"))

    # --- Hypotheses (separate evidence-chain diagram) ---
    hyp_path = out_dir / "hypotheses.json"
    if hyp_path.exists():
        try:
            raw = _load_json(hyp_path)
            if raw is None:
                raise ValueError("failed to parse JSON")
            hyp_list = raw if isinstance(raw, list) else raw.get("hypotheses", [])
            if hyp_list:
                diagram = hypotheses.generate(hyp_list)
                body = "_Source: `hypotheses.json`_\n\n```mermaid\n{diagram}\n```".format(diagram=diagram)
                sections.append(_section("Hypotheses,Evidence Chain", body))
        except Exception as exc:
            sections.append(_section("Hypotheses,Evidence Chain", f"> Could not render `hypotheses.json`: {exc}"))

    # --- Attack paths ---
    paths_path = out_dir / "attack-paths.json"
    if paths_path.exists():
        try:
            data = _load_json(paths_path)
            if data is None:
                raise ValueError("failed to parse JSON")
            if isinstance(data, dict):
                data = data.get("paths") or data.get("attack_paths") or next(iter(data.values()), [])
            if isinstance(data, list) and data:
                body = f"_Source: `attack-paths.json`_\n\n" + attack_paths.generate(data)
                sections.append(_section("Attack Paths", body))
        except Exception as exc:
            sections.append(_section("Attack Paths", f"> Could not render `attack-paths.json`: {exc}"))

    if len(sections) <= 1:
        sections.append("> No renderable JSON outputs found in this directory.\n")

    return "\n".join(sections)


def _load_optional_list(path: Path) -> list | None:
    """Load a JSON file that contains a list, either bare or in a dict envelope.

    Handles both bare lists ([...]) and single-key dict envelopes ({"paths": [...]}).
    Returns None if the file is missing, unreadable, or no list can be found.
    """
    data = _load_json(path)
    if data is None:
        return None
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                return v
    return None


def _load_disproven(path: Path) -> list | None:
    """Load disproven.json,unwraps the {'disproven': [...]} envelope."""
    data = _load_json(path)
    if data is None:
        return None
    if isinstance(data, dict):
        return data.get("disproven", [])
    return data if isinstance(data, list) else None


def render_and_write(out_dir: Path, target: Optional[str] = None) -> Path:
    content = render_directory(out_dir, target)
    output_path = out_dir / "diagrams.md"
    output_path.write_text(content, encoding="utf-8")
    return output_path
