"""Read/query helpers for RAPTOR's internal understand graph."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

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
