"""Read/query helpers for RAPTOR's internal understand graph."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional, Sequence

from .schema import json_loads
from .store import graph_path_for_run, open_graph


def graph_summary(db_path: Path) -> dict[str, Any]:
    if not Path(db_path).exists():
        return {"exists": False}
    with open_graph(db_path) as conn:
        node_counts = {
            row["kind"]: row["count"]
            for row in conn.execute("SELECT kind, COUNT(*) AS count FROM nodes WHERE stale=0 GROUP BY kind")
        }
        edge_counts = {
            row["kind"]: row["count"]
            for row in conn.execute("SELECT kind, COUNT(*) AS count FROM edges WHERE stale=0 GROUP BY kind")
        }
        latest = conn.execute(
            "SELECT * FROM snapshots ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return {
            "exists": True,
            "path": str(Path(db_path)),
            "latest_snapshot": dict(latest) if latest else None,
            "nodes": node_counts,
            "edges": edge_counts,
        }


def build_context_map(db_path: Path, target_path: Optional[str] = None) -> tuple[dict[str, Any], set[str]]:
    """Rebuild a context-map-compatible dict from graph rows."""
    if not Path(db_path).exists():
        return {}, set()
    with open_graph(db_path) as conn:
        snapshot = _latest_snapshot(conn, target_path)
        if not snapshot:
            return {}, set()
        stale_files = _stale_files_for_snapshot(conn, snapshot, target_path)
        sections = {
            "entry_points": [],
            "sources": [],
            "trust_boundaries": [],
            "boundary_details": [],
            "sinks": [],
            "sink_details": [],
            "hardcoded_secrets": [],
            "unchecked_flows": [],
        }
        rows = conn.execute(
            "SELECT * FROM nodes WHERE snapshot_id=? AND stale=0 ORDER BY kind, name, file, line_start",
            (snapshot["id"],),
        ).fetchall()
        for row in rows:
            props = json_loads(row["props_json"])
            _backfill_node_props(props, row)
            file = props.get("file") or props.get("path") or row["file"]
            if file and file in stale_files:
                continue
            section = props.get("_context_section")
            kind = row["kind"]
            if section in sections:
                sections[section].append(props)
            elif kind == "entry_point":
                sections["entry_points"].append(props)
            elif kind == "source":
                sections["sources"].append(props)
            elif kind == "trust_boundary":
                sections["trust_boundaries"].append(props)
            elif kind == "sink":
                sections["sink_details"].append(props)
            elif kind == "finding":
                sections["hardcoded_secrets"].append(props)
            elif kind == "unchecked_flow":
                sections["unchecked_flows"].append(props)
        context_map = {k: v for k, v in sections.items() if v}
        context_map["meta"] = {
            "target": snapshot["target_path"],
            "source": "understand_graph",
            "graph_db": str(Path(db_path)),
            "snapshot_id": snapshot["id"],
        }
        return context_map, stale_files


def _backfill_node_props(props: dict[str, Any], row: Any) -> None:
    """Add stable node-row fields that older ingests did not store in props."""
    row_name = row["name"] if "name" in row.keys() else None
    row_file = row["file"] if "file" in row.keys() else None
    row_line = row["line_start"] if "line_start" in row.keys() else None
    if row_name and not props.get("name"):
        props["name"] = row_name
    if row_file and not props.get("file"):
        props["file"] = row_file
    if row_line and not props.get("line"):
        props["line"] = row_line
    if row["kind"] == "entry_point":
        if row_name and not props.get("entry") and not props.get("path"):
            props["entry"] = row_name
    elif row["kind"] == "sink":
        if row_name and not props.get("operation") and not props.get("location"):
            props["operation"] = row_name


def reachable_sinks(db_path: Path, target_path: Optional[str] = None) -> list[dict[str, Any]]:
    if not Path(db_path).exists():
        return []
    with open_graph(db_path) as conn:
        snapshot = _latest_snapshot(conn, target_path)
        if not snapshot:
            return []
        rows = conn.execute(
            """
            SELECT e.confidence, e.evidence_json,
                   s.name AS source_name, s.file AS source_file, s.line_start AS source_line, s.props_json AS source_props,
                   d.name AS sink_name, d.file AS sink_file, d.line_start AS sink_line, d.props_json AS sink_props
            FROM edges e
            JOIN nodes s ON s.id=e.src_id
            JOIN nodes d ON d.id=e.dst_id
            WHERE e.snapshot_id=? AND e.kind='REACHES' AND e.stale=0
              AND s.kind IN ('entry_point', 'source') AND d.kind='sink'
            ORDER BY d.file, d.line_start
            """,
            (snapshot["id"],),
        ).fetchall()
        return [
            {
                "source": row["source_name"],
                "source_file": row["source_file"],
                "source_line": row["source_line"],
                "sink": row["sink_name"],
                "sink_file": row["sink_file"],
                "sink_line": row["sink_line"],
                "confidence": row["confidence"],
                "evidence": json_loads(row["evidence_json"]),
            }
            for row in rows
        ]


def attack_paths(
    db_path: Path,
    target_path: Optional[str] = None,
    *,
    source: Optional[str] = None,
    sink: Optional[str] = None,
    unchecked_only: bool = False,
    by_cwe: Optional[str] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Return source-to-sink paths reconstructed from graph memory.

    This is intentionally context-map-shaped rather than raw SQL-shaped: callers
    get entry, optional trust-boundary hops, sink, confidence, and evidence in a
    form that can be handed to /validate, /threat-model, or operator output.
    """
    context_map, stale = build_context_map(db_path, target_path)
    if not context_map:
        return []

    entries = _index_by_id(context_map.get("entry_points") or context_map.get("sources") or [])
    sinks = _index_by_id(context_map.get("sink_details") or context_map.get("sinks") or [])
    boundaries = [b for b in context_map.get("boundary_details") or [] if isinstance(b, dict)]
    flows = [f for f in context_map.get("unchecked_flows") or [] if isinstance(f, dict)]

    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for flow in flows:
        for ep_id in _ids(flow.get("entry_point")):
            for sink_id in _ids(flow.get("sink")):
                by_pair.setdefault((ep_id, sink_id), []).append(flow)

    out: list[dict[str, Any]] = []
    for sink_id, sink_entry in sinks.items():
        reaches = _ids(sink_entry.get("reaches_from"))
        if not reaches:
            reaches = [ep_id for ep_id, sid in by_pair if sid == sink_id]
        for ep_id in reaches:
            entry = entries.get(ep_id)
            if not entry:
                continue
            matching_flows = by_pair.get((ep_id, sink_id), [])
            if unchecked_only and not matching_flows:
                continue
            path_boundaries = [
                b for b in boundaries
                if ep_id in _ids(b.get("covers"))
            ]
            item = _path_item(
                context_map,
                ep_id,
                entry,
                sink_id,
                sink_entry,
                path_boundaries,
                matching_flows,
                stale,
            )
            if source and not _matches_path_filter(item["entry"], source):
                continue
            if sink and not _matches_path_filter(item["sink"], sink):
                continue
            if by_cwe and not _path_has_cwe(item, by_cwe):
                continue
            out.append(item)

    out.sort(key=lambda p: (
        0 if p.get("unchecked") else 1,
        -int(p.get("risk_score") or 0),
        str(p.get("entry", {}).get("id") or ""),
        str(p.get("sink", {}).get("id") or ""),
    ))
    return out[:max(1, int(limit or 50))]


def graph_diff(
    db_path: Path,
    target_path: Optional[str] = None,
    *,
    base_snapshot: Optional[str] = None,
    head_snapshot: Optional[str] = None,
) -> dict[str, Any]:
    """Compare two graph snapshots and return attack-surface drift."""
    if not Path(db_path).exists():
        return {"exists": False, "reason": "graph not found"}
    with open_graph(db_path) as conn:
        base, head = _select_diff_snapshots(
            conn,
            target_path,
            base_snapshot=base_snapshot,
            head_snapshot=head_snapshot,
        )
        if not base or not head:
            return {"exists": True, "is_diffable": False, "reason": "need at least two snapshots"}
        base_nodes = _snapshot_node_index(conn, base["id"])
        head_nodes = _snapshot_node_index(conn, head["id"])
        base_edges = _snapshot_reachability_index(conn, base["id"])
        head_edges = _snapshot_reachability_index(conn, head["id"])

    interesting = ("entry_point", "source", "trust_boundary", "sink", "unchecked_flow")
    node_diff: dict[str, Any] = {}
    for kind in interesting:
        old = {k: v for k, v in base_nodes.items() if v.get("kind") == kind}
        new = {k: v for k, v in head_nodes.items() if v.get("kind") == kind}
        node_diff[kind] = {
            "added": [_public_node(new[k]) for k in sorted(set(new) - set(old))],
            "removed": [_public_node(old[k]) for k in sorted(set(old) - set(new))],
        }

    added_reachability = [
        head_edges[k] for k in sorted(set(head_edges) - set(base_edges))
    ]
    removed_reachability = [
        base_edges[k] for k in sorted(set(base_edges) - set(head_edges))
    ]
    return {
        "exists": True,
        "is_diffable": True,
        "base_snapshot": _snapshot_public(base),
        "head_snapshot": _snapshot_public(head),
        "nodes": node_diff,
        "reachability": {
            "added": added_reachability,
            "removed": removed_reachability,
        },
        "new_risks": [
            edge for edge in added_reachability
            if edge.get("unchecked") or edge.get("confidence") in {"high", "confirmed"}
        ],
        "is_drifted": any(
            node_diff[k]["added"] or node_diff[k]["removed"]
            for k in node_diff
        ) or bool(added_reachability or removed_reachability),
    }


def threat_model_graph_context(
    db_path: Path,
    target_path: Optional[str] = None,
    *,
    limit: int = 8,
) -> str:
    """Return a compact graph-risk block for threat-model/agent prompts."""
    paths = attack_paths(
        db_path,
        target_path,
        unchecked_only=True,
        limit=limit,
    )
    if not paths:
        return ""
    lines = ["Graph-backed risks from /understand memory:"]
    for path in paths:
        entry = _node_label(path.get("entry") or {})
        sink = _node_label(path.get("sink") or {})
        missing = path.get("missing_boundary") or "unchecked flow"
        confidence = path.get("confidence") or "candidate"
        lines.append(f"- {entry} -> {sink}: {missing} ({confidence})")
    return "\n".join(lines)


def prompt_context_for_location(db_path: Path, file_path: str, line: int | None = None, *, limit: int = 6) -> str:
    """Return a compact, prompt-safe graph memory block for one finding."""
    if not file_path or not Path(db_path).exists():
        return ""
    file_name = str(file_path)
    with open_graph(db_path) as conn:
        rows = conn.execute(
            """
            SELECT kind, name, file, line_start, props_json
            FROM nodes
            WHERE stale=0 AND file=?
              AND kind IN ('entry_point', 'trust_boundary', 'sink', 'unchecked_flow', 'finding')
            ORDER BY kind, ABS(COALESCE(line_start, 0) - ?)
            LIMIT ?
            """,
            (file_name, int(line or 0), limit),
        ).fetchall()
        if not rows:
            rows = conn.execute(
                """
                SELECT kind, name, file, line_start, props_json
                FROM nodes
                WHERE stale=0 AND file LIKE ?
                  AND kind IN ('entry_point', 'trust_boundary', 'sink', 'unchecked_flow', 'finding')
                ORDER BY kind, line_start
                LIMIT ?
                """,
                (f"%{Path(file_name).name}", limit),
            ).fetchall()
    if not rows:
        return ""
    lines = ["Graph memory from prior /understand runs:"]
    for row in rows:
        props = json_loads(row["props_json"])
        label = props.get("id") or row["name"] or props.get("type") or row["kind"]
        location = row["file"] or props.get("file") or ""
        if row["line_start"]:
            location = f"{location}:{row['line_start']}"
        lines.append(f"- {row['kind']}: {label} @ {location}")
    return "\n".join(lines)


def graph_path_for_target(run_dir: Path, target_path: Optional[str]) -> Path:
    return graph_path_for_run(run_dir, target_path)


def _ids(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)] if value != "" else []


def _index_by_id(items: Sequence[Any]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id") or item.get("entry") or item.get("name") or f"item-{i + 1}")
        indexed[item_id] = item
    return indexed


def _node_label(item: dict[str, Any]) -> str:
    return str(
        item.get("name")
        or item.get("entry")
        or item.get("path")
        or item.get("operation")
        or item.get("location")
        or item.get("type")
        or item.get("id")
        or "?"
    )


def _node_location(item: dict[str, Any]) -> str:
    file = item.get("file") or item.get("path") or ""
    line = item.get("line") or item.get("line_start") or ""
    return f"{file}:{line}" if file and line else str(file or "")


def _path_item(
    context_map: dict[str, Any],
    ep_id: str,
    entry: dict[str, Any],
    sink_id: str,
    sink: dict[str, Any],
    boundaries: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    stale_files: set[str],
) -> dict[str, Any]:
    primary_flow = flows[0] if flows else {}
    confidence = str(
        primary_flow.get("confidence")
        or sink.get("confidence")
        or entry.get("confidence")
        or ("candidate" if flows else "inferred")
    )
    unchecked = bool(flows)
    missing = str(
        primary_flow.get("missing_boundary")
        or primary_flow.get("notes")
        or ("no mapped trust boundary" if not boundaries else "")
    )
    evidence = {
        "oracle": "understand_graph",
        "confirmed": bool(primary_flow.get("confirmed") or sink.get("confirmed")),
        "reproducible": False,
        "source": context_map.get("meta", {}).get("source", "understand_graph"),
        "graph_db": context_map.get("meta", {}).get("graph_db"),
        "snapshot_id": context_map.get("meta", {}).get("snapshot_id"),
        "flow": primary_flow,
        "stale_files_excluded": sorted(stale_files),
    }
    steps: list[dict[str, Any]] = [{
        "step": 1,
        "type": "entry",
        "id": ep_id,
        "action": _node_label(entry),
        "result": _node_location(entry),
    }]
    for idx, boundary in enumerate(boundaries, start=2):
        steps.append({
            "step": idx,
            "type": "trust_boundary",
            "id": boundary.get("id"),
            "action": _node_label(boundary),
            "result": _node_location(boundary),
        })
    steps.append({
        "step": len(steps) + 1,
        "type": "sink",
        "id": sink_id,
        "action": _node_label(sink),
        "result": _node_location(sink),
    })
    return {
        "id": f"graph-path-{ep_id}-{sink_id}",
        "entry": {"id": ep_id, "label": _node_label(entry), "location": _node_location(entry), "raw": entry},
        "sink": {"id": sink_id, "label": _node_label(sink), "location": _node_location(sink), "raw": sink},
        "trust_boundaries": [
            {"id": b.get("id"), "label": _node_label(b), "location": _node_location(b), "raw": b}
            for b in boundaries
        ],
        "steps": steps,
        "unchecked": unchecked,
        "missing_boundary": missing,
        "confidence": confidence,
        "cwe": _collect_cwes(entry, sink, primary_flow),
        "evidence": evidence,
        "risk_score": _risk_score(unchecked, confidence, sink, primary_flow),
    }


def _matches_path_filter(item: dict[str, Any], needle: str) -> bool:
    text = " ".join(str(v) for v in (
        item.get("id"),
        item.get("label"),
        item.get("location"),
    ) if v).lower()
    return str(needle).lower() in text


def _collect_cwes(*items: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in ("cwe", "cwe_id", "cwes"):
            value = item.get(key)
            if isinstance(value, list):
                cwes.extend(str(v) for v in value if v)
            elif value:
                cwes.append(str(value))
    return sorted(set(cwes))


def _path_has_cwe(path: dict[str, Any], cwe: str) -> bool:
    wanted = str(cwe).lower()
    return any(wanted in str(item).lower() for item in path.get("cwe") or [])


def _risk_score(unchecked: bool, confidence: str, sink: dict[str, Any], flow: dict[str, Any]) -> int:
    score = 60 if unchecked else 35
    conf = str(confidence or "").lower()
    if conf in {"confirmed", "high"}:
        score += 20
    elif conf == "medium":
        score += 10
    severity = str(flow.get("severity") or sink.get("severity") or "").lower()
    if severity in {"critical", "high"}:
        score += 15
    return min(score, 100)


def _select_diff_snapshots(conn, target_path: Optional[str], *, base_snapshot: Optional[str], head_snapshot: Optional[str]):
    if base_snapshot:
        base = _snapshot_by_id(conn, base_snapshot)
    else:
        base = None
    if head_snapshot:
        head = _snapshot_by_id(conn, head_snapshot)
    else:
        head = None
    if base and head:
        return base, head
    params: tuple[Any, ...]
    if target_path:
        rows = conn.execute(
            """
            SELECT * FROM snapshots
            WHERE target_path=? OR target_path=?
            ORDER BY created_at DESC LIMIT 2
            """,
            (str(target_path), str(Path(target_path).resolve())),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM snapshots ORDER BY created_at DESC LIMIT 2"
        ).fetchall()
    if not head and rows:
        head = rows[0]
    if not base and len(rows) > 1:
        base = rows[1]
    return base, head


def _snapshot_by_id(conn, snapshot: str):
    return conn.execute(
        "SELECT * FROM snapshots WHERE id=?",
        (snapshot,),
    ).fetchone()


def _snapshot_node_index(conn, snapshot_id: str) -> dict[str, dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM nodes WHERE snapshot_id=? AND stale=0",
        (snapshot_id,),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        props = json_loads(row["props_json"])
        _backfill_node_props(props, row)
        key = row["stable_key"]
        out[key] = {
            "id": row["id"],
            "kind": row["kind"],
            "stable_key": key,
            "name": row["name"],
            "file": row["file"],
            "line": row["line_start"],
            "props": props,
        }
    return out


def _snapshot_reachability_index(conn, snapshot_id: str) -> dict[str, dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT e.*, s.stable_key AS src_key, s.name AS src_name, s.file AS src_file,
               s.kind AS src_kind, d.stable_key AS dst_key, d.name AS dst_name,
               d.file AS dst_file, d.kind AS dst_kind
        FROM edges e
        JOIN nodes s ON s.id=e.src_id
        JOIN nodes d ON d.id=e.dst_id
        WHERE e.snapshot_id=? AND e.kind='REACHES' AND e.stale=0
          AND s.kind IN ('entry_point', 'source') AND d.kind='sink'
        """,
        (snapshot_id,),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        evidence = json_loads(row["evidence_json"])
        key = f"{row['src_key']}->{row['dst_key']}"
        out[key] = {
            "source": row["src_name"],
            "source_file": row["src_file"],
            "sink": row["dst_name"],
            "sink_file": row["dst_file"],
            "confidence": row["confidence"],
            "unchecked": bool(isinstance(evidence, dict) and evidence.get("missing_boundary")),
            "evidence": evidence,
        }
    return out


def _public_node(node: dict[str, Any]) -> dict[str, Any]:
    props = node.get("props") or {}
    return {
        "id": props.get("id") or node.get("id"),
        "kind": node.get("kind"),
        "name": props.get("name") or node.get("name"),
        "file": props.get("file") or node.get("file"),
        "line": props.get("line") or node.get("line"),
        "confidence": props.get("confidence") or props.get("graph_evidence", {}).get("confidence"),
        "evidence": props.get("graph_evidence"),
    }


def _snapshot_public(snapshot) -> dict[str, Any]:
    return {
        "id": snapshot["id"],
        "target_path": snapshot["target_path"],
        "created_at": snapshot["created_at"],
        "producer_run": snapshot["producer_run"],
        "git_sha": snapshot["git_sha"],
    }


def _latest_snapshot(conn, target_path: Optional[str]):
    if target_path:
        rows = conn.execute(
            """
            SELECT * FROM snapshots
            WHERE target_path=? OR target_path=?
            ORDER BY created_at DESC LIMIT 1
            """,
            (str(target_path), str(Path(target_path).resolve())),
        ).fetchall()
        if rows:
            return rows[0]
    return conn.execute("SELECT * FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()


def _stale_files_for_snapshot(conn, snapshot, target_path: Optional[str]) -> set[str]:
    if not target_path:
        return set()
    try:
        from core.hash import sha256_file
    except Exception:
        return set()
    stale: set[str] = set()
    target = Path(target_path)
    rows = conn.execute(
        "SELECT file, props_json FROM nodes WHERE snapshot_id=? AND kind='file'",
        (snapshot["id"],),
    ).fetchall()
    for row in rows:
        props = json_loads(row["props_json"])
        rel = props.get("path") or row["file"]
        expected = props.get("sha256")
        if not rel or not expected:
            continue
        full = target / rel
        if not full.is_file():
            stale.add(rel)
            continue
        try:
            if sha256_file(full) != expected:
                stale.add(rel)
        except OSError:
            stale.add(rel)
    return stale
