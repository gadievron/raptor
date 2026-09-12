"""
Diagram renderer: discovers JSON outputs in an /understand or /validate output
directory and produces a consolidated diagrams.md with all Mermaid charts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.artifacts.provenance import provenance_of
from core.json import load_json as _load_json
from core.security.prompt_output_sanitise import sanitise_code, sanitise_string

from . import context_map, flow_trace, attack_tree, attack_paths, hypotheses, findings_summary, graph_memory, edge_obligations
from .sanitize import detect_id_collisions, sanitize as _sanitize


_FLOW_TRACE_GLOB = "flow-trace-*.json"
_GRAPH_FILENAME = "raptor.graph.sqlite"


def _section(title: str, body: str, level: int = 2) -> str:
    heading = "#" * level
    title = " ".join(str(title).split()).strip()
    return f"{heading} {title}\n\n{body}\n"


def _fence(diagram: str) -> str:
    """Defang a generated diagram string before embedding in ```mermaid.

    The generators label-sanitise via ``packages.diagram.sanitize``, but
    the renderer is the last hop before the string lands inside a
    markdown fence — ``sanitise_code`` neutralises embedded 3+ backtick
    runs (zero-width space after the second backtick) and escapes
    ANSI/BIDI/control bytes so a crafted JSON value that survived a
    generator cannot terminate the fence and spill live markdown.
    Benign Mermaid text (no backtick runs, printable chars) is unchanged.
    """
    return sanitise_code(str(diagram), max_chars=200_000)


def _err(exc: object) -> str:
    return sanitise_string(" ".join(str(exc).split()), max_chars=300)


def _id_collision_warning(data: object) -> str:
    if not isinstance(data, dict):
        return ""
    raw_ids = [
        n.get("id", "?") for n in data.get("nodes", [])
        if isinstance(n, dict)
    ]
    root = data.get("root")
    if root is not None:
        raw_ids.append(root)
    collisions = detect_id_collisions(raw_ids)
    if not collisions:
        return ""
    shown = "; ".join(
        "%s → `%s`" % (
            ", ".join(
                f"`{_sanitize(r, 40)}`" for r in sorted(set(raws))
            ),
            sanitized,
        )
        for sanitized, raws in collisions[:5]
    )
    more = "" if len(collisions) <= 5 else f" (+{len(collisions) - 5} more)"
    return (
        f"\n\n> Warning: {len(collisions)} node-ID collision(s) after "
        f"sanitization — distinct source nodes render as one Mermaid "
        f"node: {shown}{more}. Rename the colliding ids in "
        f"`attack-tree.json` to disambiguate."
    )


def _provenance_note(data: object) -> str:
    prov = provenance_of(data)
    if prov["legacy"] or not prov["untrusted"]:
        return ""
    generator = sanitise_string(
        " ".join(str(prov["generator"]).split()), max_chars=60,
    ).replace("`", "\\`")
    return (
        f"\n\n_Provenance: LLM-derived content (untrusted), generator "
        f"`{generator}` — verify against source before acting._"
    )


def _graph_path_for_directory(out_dir: Path) -> Optional[Path]:
    direct = out_dir / "graph" / _GRAPH_FILENAME
    if direct.exists():
        return direct

    checklist = _load_json(out_dir / "checklist.json") if (out_dir / "checklist.json").exists() else None
    target_path = checklist.get("target_path") if isinstance(checklist, dict) else None
    if not target_path:
        return None

    from core.understand_graph import graph_path_for_run

    graph_path = graph_path_for_run(out_dir, target_path)
    return graph_path if graph_path.exists() else None


def render_directory(out_dir: Path, target: Optional[str] = None) -> str:
    out_dir = Path(out_dir)
    sections: list[str] = []

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    safe_target = (target or "").replace("`", "\\`")
    target_str = f" for `{safe_target}`" if target else ""
    sections.append(f"# Security Diagrams{target_str}\n\n_Generated {now}_\n")

    # --- Findings summary pies (exec summary, shown first) ---
    findings_path = out_dir / "findings.json"
    orch_path_early = out_dir / "orchestrated_report.json"
    summary_findings = None
    if findings_path.exists():
        fdata = _load_json(findings_path)
        if fdata and isinstance(fdata, dict):
            f_list = fdata.get("findings")
            if isinstance(f_list, list):
                summary_findings = [r for r in f_list if isinstance(r, dict)]
    elif orch_path_early.exists():
        odata = _load_json(orch_path_early)
        if odata and isinstance(odata, dict):
            results = odata.get("results")
            if isinstance(results, list):
                summary_findings = [
                    r for r in results
                    if isinstance(r, dict) and "is_true_positive" in r
                ]

    if summary_findings and len(summary_findings) >= 2:
        try:
            verdict = findings_summary.generate_verdict_pie(summary_findings)
            vtype = findings_summary.generate_type_pie(summary_findings)
            body = (
                f"```mermaid\n{_fence(verdict)}\n```\n\n"
                f"```mermaid\n{_fence(vtype)}\n```"
            )
            sections.append(_section("Findings Summary", body))
        except Exception as exc:
            sections.append(_section("Findings Summary", f"> Could not render: {_err(exc)}"))

    # --- Context map / graph memory / attack surface ---
    context_map_rendered = False
    for fname, title in [
        ("context-map.json", "Context Map, Entry Points, Trust Boundaries, Sinks"),
        ("context-map.graph.json", "Context Map from Graph Memory"),
        ("attack-surface.json", "Attack Surface (Stage B)"),
    ]:
        fpath = out_dir / fname
        if not fpath.exists():
            continue
        try:
            data = _load_json(fpath)
            if data is None:
                raise ValueError("failed to parse JSON")
            if isinstance(data, dict) and "meta" not in data and target:
                data = dict(data)
                data["meta"] = {"target": target}
            diagram = context_map.generate(data)
            body = (f"_Source: `{fname}`_{_provenance_note(data)}"
                    f"\n\n```mermaid\n{_fence(diagram)}\n```")
            sections.append(_section(title, body))
            if fname.startswith("context-map"):
                context_map_rendered = True
            try:
                fr_blocks = context_map.generate_forward_reachable_blocks(
                    data,
                )
            except Exception as exc:
                fr_blocks = []
                sections.append(_section(
                    f"{title} — Forward Reachability",
                    f"> Could not render forward-reachable blocks: {_err(exc)}",
                ))
            if fr_blocks:
                sub_sections: list[str] = []
                for sub_title, sub_diagram in fr_blocks:
                    sub_sections.append(_section(
                        sub_title,
                        f"```mermaid\n{_fence(sub_diagram)}\n```",
                        level=3,
                    ))
                sections.append(_section(
                    f"{title} — Forward Reachability per Entry Point",
                    "_Source: `" + fname + "` (`forward_reachable` "
                    "field per entry, populated by "
                    "`raptor-enrich-context-map-callgraph`)_\n\n"
                    + "\n".join(sub_sections),
                ))
        except Exception as exc:
            sections.append(_section(title, f"> Could not render `{fname}`: {_err(exc)}"))

    if not context_map_rendered:
        try:
            from core.understand_graph import build_context_map
            graph_path = _graph_path_for_directory(out_dir)
            if graph_path and graph_path.exists():
                data, stale = build_context_map(graph_path)
                if data:
                    diagram = context_map.generate(data)
                    stale_note = (
                        f"\n\n_Stale files excluded: {len(stale)}_"
                        if stale else ""
                    )
                    body = (
                        f"_Source: `{graph_path}` (persistent /understand graph)_"
                        f"{stale_note}\n\n```mermaid\n{_fence(diagram)}\n```"
                    )
                    sections.append(_section(
                        "Context Map from Graph Memory",
                        body,
                    ))
        except Exception as exc:
            sections.append(_section(
                "Context Map from Graph Memory",
                f"> Could not render graph memory: {_err(exc)}",
            ))

    # --- Edge obligations (--edges) ---
    eo_path = out_dir / "edge-obligations.json"
    if eo_path.exists():
        try:
            data = _load_json(eo_path)
            if data is None:
                raise ValueError("failed to parse JSON")
            diagram = edge_obligations.generate(data)
            body = ("_Source: `edge-obligations.json`_\n\n"
                    f"```mermaid\n{_fence(diagram)}\n```")
            sections.append(_section(
                "Edge Obligations (tier-1 solid, tier-2 dashed)", body))
        except Exception as exc:
            sections.append(_section(
                "Edge Obligations",
                f"> Could not render `edge-obligations.json`: {_err(exc)}"))

    # --- Flow traces ---
    trace_files = sorted(out_dir.glob(_FLOW_TRACE_GLOB))
    if trace_files:
        trace_sections: list[str] = []
        for tf in trace_files:
            try:
                data = _load_json(tf)
                if data is None:
                    raise ValueError("failed to parse JSON")
                raw_id = data.get("id", tf.stem)
                trace_id = _sanitize(raw_id)
                name = _sanitize(data.get("name", raw_id))
                diagram = flow_trace.generate(data)
                body = (f"_Source: `{tf.name}`_{_provenance_note(data)}"
                        f"\n\n```mermaid\n{_fence(diagram)}\n```")
                heading = f"{trace_id}: {name}".replace("\n", " ").replace("\r", " ")
                trace_sections.append(_section(heading, body, level=3))
            except Exception as exc:
                trace_sections.append(_section(tf.stem, f"> Could not render `{tf.name}`: {_err(exc)}", level=3))
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
            body = (f"_Source: `attack-tree.json`_{note}{_provenance_note(data)}"
                    f"\n\n```mermaid\n{_fence(diagram)}\n```"
                    f"{_id_collision_warning(data)}")
            sections.append(_section("Attack Tree", body))
        except Exception as exc:
            sections.append(_section("Attack Tree", f"> Could not render `attack-tree.json`: {_err(exc)}"))

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
                body = (f"_Source: `hypotheses.json`_{_provenance_note(raw)}"
                        f"\n\n```mermaid\n{_fence(diagram)}\n```")
                sections.append(_section("Hypotheses,Evidence Chain", body))
        except Exception as exc:
            sections.append(_section("Hypotheses,Evidence Chain", f"> Could not render `hypotheses.json`: {_err(exc)}"))

    # --- Graph-priority paths (Stage 0 graph handoff) ---
    graph_paths_path = out_dir / "graph-priority-paths.json"
    if graph_paths_path.exists():
        try:
            data = _load_json(graph_paths_path)
            if data is None:
                raise ValueError("failed to parse JSON")
            if isinstance(data, dict):
                data = data.get("paths") or data.get("graph_paths") or data.get("items") or []
            if isinstance(data, list):
                diagram = graph_memory.generate_priority_paths(data)
                body = f"_Source: `graph-priority-paths.json`_\n\n```mermaid\n{_fence(diagram)}\n```"
                sections.append(_section("Graph Priority Paths", body))
        except Exception as exc:
            sections.append(_section("Graph Priority Paths", f"> Could not render `graph-priority-paths.json`: {_err(exc)}"))

    # --- Attack paths ---
    paths_path = out_dir / "attack-paths.json"
    if paths_path.exists():
        try:
            data = _load_json(paths_path)
            if data is None:
                raise ValueError("failed to parse JSON")
            prov_note = _provenance_note(data)
            if isinstance(data, dict):
                data = data.get("paths") or data.get("attack_paths") or next(iter(data.values()), [])
            if isinstance(data, list) and data:
                body = (f"_Source: `attack-paths.json`_{prov_note}\n\n"
                        + attack_paths.generate(data))
                sections.append(_section("Attack Paths", body))
        except Exception as exc:
            sections.append(_section("Attack Paths", f"> Could not render `attack-paths.json`: {_err(exc)}"))

    # --- Graph diff output ---
    for diff_name in ("graph-diff.json", "understand-graph-diff.json"):
        diff_path = out_dir / diff_name
        if not diff_path.exists():
            continue
        try:
            data = _load_json(diff_path)
            if data is None:
                raise ValueError("failed to parse JSON")
            if isinstance(data, dict):
                diagram = graph_memory.generate_diff(data)
                body = f"_Source: `{diff_name}`_\n\n```mermaid\n{_fence(diagram)}\n```"
                sections.append(_section("Graph Snapshot Diff", body))
        except Exception as exc:
            sections.append(_section("Graph Snapshot Diff", f"> Could not render `{diff_name}`: {_err(exc)}"))

    if len(sections) <= 1:
        sections.append("> No renderable JSON outputs found in this directory.\n")

    return "\n".join(sections)


def _load_optional_list(path: Path) -> list | None:
    """Load a JSON file that contains a list, either bare or in a dict envelope.

    Handles bare lists ([...]) and dict envelopes. Envelopes are
    unwrapped by KNOWN payload key first; a positional
    first-list-value fallback is accepted only when the dict carries
    exactly ONE list — with several, "whichever list comes first" can
    silently return a metadata array instead of the payload.
    Returns None if the file is missing, unreadable, or no list can
    be found.
    """
    data = _load_json(path)
    if data is None:
        return None
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("paths", "attack_paths", "hypotheses"):
            v = data.get(key)
            if isinstance(v, list):
                return v
        lists = [v for v in data.values() if isinstance(v, list)]
        if len(lists) == 1:
            return lists[0]
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
