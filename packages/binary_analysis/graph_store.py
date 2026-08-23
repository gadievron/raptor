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
from typing import Any, Self, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

GRAPH_FILENAME = "binary-graph.sqlite"
SCHEMA_VERSION = 2


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
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _migrate(conn)
    except BaseException:
        conn.close()
        raise
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
        msg = f"binary graph schema version {current} is newer than this RAPTOR ({SCHEMA_VERSION})"
        raise RuntimeError(msg)
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
                PRIMARY KEY(snapshot_id, node_id, evidence_id),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS edge_evidence (
                snapshot_id TEXT NOT NULL,
                edge_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                PRIMARY KEY(snapshot_id, edge_id, evidence_id),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                snapshot_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(snapshot_id, kind, path),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_binary_nodes_kind ON nodes(snapshot_id, kind);
            CREATE INDEX IF NOT EXISTS idx_binary_edges_kind ON edges(snapshot_id, kind);
            CREATE INDEX IF NOT EXISTS idx_binary_evidence_tier ON evidence(snapshot_id, tier);
            """
        )
    elif current == 1:
        _upgrade_v1_to_v2(conn)
    conn.execute(f"PRAGMA user_version={int(SCHEMA_VERSION)}")
    conn.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
        ("schema_version", str(SCHEMA_VERSION)),
    )


def _upgrade_v1_to_v2(conn: sqlite3.Connection) -> None:
    """v1 omitted the snapshot FK on node_evidence/edge_evidence/artifacts,
    so a snapshot REPLACE cascaded nodes/edges/evidence but orphaned these
    rows. SQLite cannot add a FK in place; rebuild each table and drop rows
    already orphaned."""
    conn.executescript(
        """
        BEGIN;
        ALTER TABLE node_evidence RENAME TO node_evidence_v1;
        CREATE TABLE node_evidence (
            snapshot_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            PRIMARY KEY(snapshot_id, node_id, evidence_id),
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );
        INSERT INTO node_evidence(snapshot_id, node_id, evidence_id)
            SELECT snapshot_id, node_id, evidence_id FROM node_evidence_v1
            WHERE snapshot_id IN (SELECT id FROM snapshots);
        DROP TABLE node_evidence_v1;

        ALTER TABLE edge_evidence RENAME TO edge_evidence_v1;
        CREATE TABLE edge_evidence (
            snapshot_id TEXT NOT NULL,
            edge_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            PRIMARY KEY(snapshot_id, edge_id, evidence_id),
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );
        INSERT INTO edge_evidence(snapshot_id, edge_id, evidence_id)
            SELECT snapshot_id, edge_id, evidence_id FROM edge_evidence_v1
            WHERE snapshot_id IN (SELECT id FROM snapshots);
        DROP TABLE edge_evidence_v1;

        ALTER TABLE artifacts RENAME TO artifacts_v1;
        CREATE TABLE artifacts (
            snapshot_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            path TEXT NOT NULL,
            sha256 TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(snapshot_id, kind, path),
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );
        INSERT INTO artifacts(snapshot_id, kind, path, sha256)
            SELECT snapshot_id, kind, path, sha256 FROM artifacts_v1
            WHERE snapshot_id IN (SELECT id FROM snapshots);
        DROP TABLE artifacts_v1;
        COMMIT;
        """
    )


class BinaryGraphStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._conn: sqlite3.Connection | None = None
        self._batch_depth: int = 0

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = open_graph(self.path)
        return self._conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._get_conn()
        if self._batch_depth > 0:
            yield conn
            return
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    @contextmanager
    def batch(self) -> Iterator[BinaryGraphStore]:
        """Batch multiple operations into a single transaction.

        Defers per-operation commits until the batch exits, reducing
        overhead when ingesting many nodes/edges."""
        conn = self._get_conn()
        self._batch_depth += 1
        try:
            yield self
            if self._batch_depth == 1:
                conn.commit()
        except Exception:
            if self._batch_depth == 1:
                conn.rollback()
            raise
        finally:
            self._batch_depth -= 1

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: BLE001, S110 — broad by design: __del__ may run during interpreter teardown, where object state and module globals are unreliable; a raise here only spams stderr
            pass

    def begin_snapshot(self, binary_sha256: str, binary_path: str, run_dir: Path, props: dict[str, Any] | None = None) -> str:
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

    def latest_snapshot_id(self) -> str | None:
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
        props: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
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
        props: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
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
    with graph_connection(path) as conn:
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


def query_edges(path: Path, *, kind: str | None = None) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    with graph_connection(path) as conn:
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


def query_evidence(path: Path, *, tier: str | None = None) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    with graph_connection(path) as conn:
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
    "GRAPH_FILENAME",
    "BinaryGraphStore",
    "graph_path_for_run",
    "graph_summary",
    "open_graph",
    "query_edges",
    "query_evidence",
    "stable_edge_id",
    "stable_node_id",
]
