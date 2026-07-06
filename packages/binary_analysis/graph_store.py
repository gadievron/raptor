"""SQLite graph memory for black-box binary analysis.

The graph is a private substrate. JSON artefacts remain the public contract,
but the database gives `/understand`, fuzzing, runtime observation and future
validation passes one shared place to query evidence without re-running every
extractor.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

GRAPH_FILENAME = "binary-graph.sqlite"
SCHEMA_VERSION = 1


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"), default=str)


def _hash(*parts: Any, length: int = 20) -> str:
    data = "::".join(str(part) for part in parts).encode("utf-8", "surrogateescape")
    return hashlib.sha256(data).hexdigest()[:length]


def stable_node_id(binary_sha256: str, kind: str, key: str) -> str:
    return f"node:{kind}:{_hash(binary_sha256, kind, key)}"


def stable_edge_id(binary_sha256: str, kind: str, src_id: str, dst_id: str) -> str:
    return f"edge:{kind}:{_hash(binary_sha256, kind, src_id, dst_id)}"


def graph_path_for_run(run_dir: Path) -> Path:
    return Path(run_dir) / "graph" / GRAPH_FILENAME


def open_graph(path: Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    _migrate(conn)
    return conn


@contextmanager
def graph_connection(path: Path) -> Iterator[sqlite3.Connection]:
    conn = open_graph(path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    current = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if current > SCHEMA_VERSION:
        raise RuntimeError(
            f"binary graph schema version {current} is newer than this RAPTOR ({SCHEMA_VERSION})"
        )
    if current == 0:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id TEXT PRIMARY KEY,
                binary_sha256 TEXT NOT NULL,
                binary_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                producer_run TEXT NOT NULL,
                props_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS nodes (
                snapshot_id TEXT NOT NULL,
                id TEXT NOT NULL,
                kind TEXT NOT NULL,
                stable_key TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                address TEXT NOT NULL DEFAULT '',
                props_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(snapshot_id, id),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS edges (
                snapshot_id TEXT NOT NULL,
                id TEXT NOT NULL,
                kind TEXT NOT NULL,
                src_id TEXT NOT NULL,
                dst_id TEXT NOT NULL,
                confidence TEXT NOT NULL DEFAULT '',
                props_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(snapshot_id, id),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS evidence (
                snapshot_id TEXT NOT NULL,
                id TEXT NOT NULL,
                kind TEXT NOT NULL,
                tier TEXT NOT NULL,
                confidence TEXT NOT NULL,
                reproducible INTEGER NOT NULL,
                source TEXT NOT NULL,
                tool TEXT NOT NULL,
                summary TEXT NOT NULL,
                props_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(snapshot_id, id),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS node_evidence (
                snapshot_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                PRIMARY KEY(snapshot_id, node_id, evidence_id)
            );

            CREATE TABLE IF NOT EXISTS edge_evidence (
                snapshot_id TEXT NOT NULL,
                edge_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                PRIMARY KEY(snapshot_id, edge_id, evidence_id)
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                snapshot_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(snapshot_id, kind, path)
            );

            CREATE INDEX IF NOT EXISTS idx_binary_nodes_kind ON nodes(snapshot_id, kind);
            CREATE INDEX IF NOT EXISTS idx_binary_edges_kind ON edges(snapshot_id, kind);
            CREATE INDEX IF NOT EXISTS idx_binary_evidence_tier ON evidence(snapshot_id, tier);
            """
        )
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    conn.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
        ("schema_version", str(SCHEMA_VERSION)),
    )


class BinaryGraphStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._conn: Optional[sqlite3.Connection] = None

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = open_graph(self.path)
        return self._conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def begin_snapshot(self, binary_sha256: str, binary_path: str, run_dir: Path, props: Optional[dict[str, Any]] = None) -> str:
        snapshot_id = f"snap:{_hash(binary_sha256, str(Path(run_dir).resolve()))}"
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO snapshots
                (id, binary_sha256, binary_path, created_at, producer_run, props_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    binary_sha256,
                    binary_path,
                    datetime.now(timezone.utc).isoformat(),
                    str(Path(run_dir).resolve()),
                    _json(props or {}),
                ),
            )
        return snapshot_id

    def latest_snapshot_id(self) -> Optional[str]:
        if not self.path.exists():
            return None
        with self._connection() as conn:
            row = conn.execute("SELECT id FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
            return str(row["id"]) if row else None

    def add_evidence(self, snapshot_id: str, record: Any) -> None:
        data = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evidence
                (snapshot_id, id, kind, tier, confidence, reproducible, source, tool, summary, props_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    data["id"],
                    data["kind"],
                    data["tier"],
                    data["confidence"],
                    1 if data.get("reproducible") else 0,
                    data["source"],
                    data["tool"],
                    data["summary"],
                    _json(data),
                ),
            )

    def add_node(
        self,
        snapshot_id: str,
        binary_sha256: str,
        kind: str,
        key: str,
        *,
        name: str = "",
        address: str = "",
        props: Optional[dict[str, Any]] = None,
        evidence_ids: Optional[list[str]] = None,
    ) -> str:
        node_id = stable_node_id(binary_sha256, kind, key)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO nodes
                (snapshot_id, id, kind, stable_key, name, address, props_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (snapshot_id, node_id, kind, key, name, address, _json(props or {})),
            )
            for evidence_id in evidence_ids or []:
                conn.execute(
                    "INSERT OR IGNORE INTO node_evidence(snapshot_id, node_id, evidence_id) VALUES (?, ?, ?)",
                    (snapshot_id, node_id, evidence_id),
                )
        return node_id

    def add_edge(
        self,
        snapshot_id: str,
        binary_sha256: str,
        kind: str,
        src_id: str,
        dst_id: str,
        *,
        confidence: str = "",
        props: Optional[dict[str, Any]] = None,
        evidence_ids: Optional[list[str]] = None,
    ) -> str:
        edge_id = stable_edge_id(binary_sha256, kind, src_id, dst_id)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO edges
                (snapshot_id, id, kind, src_id, dst_id, confidence, props_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (snapshot_id, edge_id, kind, src_id, dst_id, confidence, _json(props or {})),
            )
            for evidence_id in evidence_ids or []:
                conn.execute(
                    "INSERT OR IGNORE INTO edge_evidence(snapshot_id, edge_id, evidence_id) VALUES (?, ?, ?)",
                    (snapshot_id, edge_id, evidence_id),
                )
        return edge_id

    def add_artifact(self, snapshot_id: str, kind: str, path: Path) -> None:
        try:
            digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        except OSError:
            digest = ""
        with self._connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO artifacts(snapshot_id, kind, path, sha256) VALUES (?, ?, ?, ?)",
                (snapshot_id, kind, str(Path(path).resolve()), digest),
            )


def graph_summary(path: Path) -> dict[str, Any]:
    if not Path(path).exists():
        return {"exists": False, "path": str(path)}
    with open_graph(path) as conn:
        latest = conn.execute("SELECT * FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
        if latest is None:
            return {"exists": True, "path": str(path), "nodes": {}, "edges": {}, "evidence": {}}
        snapshot_id = latest["id"]
        nodes = {
            row["kind"]: row["count"]
            for row in conn.execute(
                "SELECT kind, COUNT(*) AS count FROM nodes WHERE snapshot_id=? GROUP BY kind",
                (snapshot_id,),
            )
        }
        edges = {
            row["kind"]: row["count"]
            for row in conn.execute(
                "SELECT kind, COUNT(*) AS count FROM edges WHERE snapshot_id=? GROUP BY kind",
                (snapshot_id,),
            )
        }
        evidence = {
            row["tier"]: row["count"]
            for row in conn.execute(
                "SELECT tier, COUNT(*) AS count FROM evidence WHERE snapshot_id=? GROUP BY tier",
                (snapshot_id,),
            )
        }
        return {
            "exists": True,
            "path": str(path),
            "latest_snapshot": dict(latest),
            "nodes": nodes,
            "edges": edges,
            "evidence": evidence,
        }


def query_edges(path: Path, *, kind: Optional[str] = None) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    with open_graph(path) as conn:
        latest = conn.execute("SELECT id FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
        if latest is None:
            return []
        params: list[Any] = [latest["id"]]
        where = "WHERE e.snapshot_id=?"
        if kind:
            where += " AND e.kind=?"
            params.append(kind)
        rows = conn.execute(
            f"""
            SELECT e.*, s.name AS src_name, s.kind AS src_kind,
                   d.name AS dst_name, d.kind AS dst_kind
            FROM edges e
            JOIN nodes s ON s.snapshot_id=e.snapshot_id AND s.id=e.src_id
            JOIN nodes d ON d.snapshot_id=e.snapshot_id AND d.id=e.dst_id
            {where}
            ORDER BY e.kind, s.name, d.name
            """,
            tuple(params),
        ).fetchall()
        return [
            {
                "id": row["id"],
                "kind": row["kind"],
                "source": {"id": row["src_id"], "kind": row["src_kind"], "name": row["src_name"]},
                "target": {"id": row["dst_id"], "kind": row["dst_kind"], "name": row["dst_name"]},
                "confidence": row["confidence"],
                "props": json.loads(row["props_json"] or "{}"),
            }
            for row in rows
        ]


def query_evidence(path: Path, *, tier: Optional[str] = None) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    with open_graph(path) as conn:
        latest = conn.execute("SELECT id FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
        if latest is None:
            return []
        params: list[Any] = [latest["id"]]
        where = "WHERE snapshot_id=?"
        if tier:
            where += " AND tier=?"
            params.append(tier)
        rows = conn.execute(
            f"""
            SELECT id, kind, tier, confidence, reproducible, source, tool, summary, props_json
            FROM evidence
            {where}
            ORDER BY tier, kind, id
            """,
            tuple(params),
        ).fetchall()
        return [
            {
                "id": row["id"],
                "kind": row["kind"],
                "tier": row["tier"],
                "confidence": row["confidence"],
                "reproducible": bool(row["reproducible"]),
                "source": row["source"],
                "tool": row["tool"],
                "summary": row["summary"],
                "props": json.loads(row["props_json"] or "{}"),
            }
            for row in rows
        ]


__all__ = [
    "BinaryGraphStore",
    "GRAPH_FILENAME",
    "graph_path_for_run",
    "graph_summary",
    "open_graph",
    "query_edges",
    "query_evidence",
    "stable_edge_id",
    "stable_node_id",
]
