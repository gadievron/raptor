"""SQLite store and migrations for RAPTOR's /understand graph."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from .schema import SCHEMA_VERSION

GRAPH_FILENAME = "raptor.graph.sqlite"


def graph_path_for_run(run_dir: Path, target_path: Optional[str] = None) -> Path:
    """Return the graph DB path for a run or project.

    Project-owned graphs are preferred when a project matches the target. For
    standalone runs, the graph lives under the run directory.
    """
    run_dir = Path(run_dir)
    try:
        from core.project.project import ProjectManager

        mgr = ProjectManager()
        run_resolved = run_dir.resolve()
        projects = mgr.list_projects()

        # Strongest signal: the caller passed a run dir that is already under a
        # project output directory. Prefer that project over any other project
        # pointing at the same target, otherwise duplicate test projects can
        # steal each other's graph memory.
        for project in projects:
            out_dir = Path(project.output_dir).resolve()
            try:
                run_resolved.relative_to(out_dir)
                return out_dir / "graph" / GRAPH_FILENAME
            except ValueError:
                continue

        active_name = mgr.get_active()
        if active_name:
            active = mgr.load(active_name)
            if active is not None:
                if not target_path:
                    return Path(active.output_dir) / "graph" / GRAPH_FILENAME
                try:
                    if Path(active.target).resolve() == Path(target_path).resolve():
                        return Path(active.output_dir) / "graph" / GRAPH_FILENAME
                except OSError:
                    pass
    except Exception:
        pass

    if target_path:
        try:
            from core.project.project import ProjectManager

            project = ProjectManager().find_project_for_target(str(target_path))
            if project is not None:
                return Path(project.output_dir) / "graph" / GRAPH_FILENAME
        except Exception:
            pass

    # If the caller passed a project root directly, use its graph directory.
    try:
        if (run_dir / ".raptor-project-root").exists():
            return run_dir / "graph" / GRAPH_FILENAME
    except OSError:
        pass
    return run_dir / "graph" / GRAPH_FILENAME


def open_graph(path: Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    migrate(conn)
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


def migrate(conn: sqlite3.Connection) -> None:
    current = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if current > SCHEMA_VERSION:
        raise RuntimeError(
            f"graph schema version {current} is newer than this RAPTOR ({SCHEMA_VERSION})"
        )
    if current < 1:
        _migrate_1(conn)
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")


def _migrate_1(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS snapshots (
            id TEXT PRIMARY KEY,
            target_path TEXT NOT NULL,
            target_hash TEXT NOT NULL DEFAULT '',
            git_sha TEXT NOT NULL DEFAULT '',
            checklist_hash TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            producer_run TEXT NOT NULL DEFAULT '',
            props_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            stable_key TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL DEFAULT '',
            file TEXT NOT NULL DEFAULT '',
            line_start INTEGER,
            line_end INTEGER,
            snapshot_id TEXT NOT NULL,
            stale INTEGER NOT NULL DEFAULT 0,
            props_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS edges (
            id TEXT PRIMARY KEY,
            src_id TEXT NOT NULL,
            dst_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT '',
            snapshot_id TEXT NOT NULL,
            stale INTEGER NOT NULL DEFAULT 0,
            evidence_json TEXT NOT NULL DEFAULT '{}',
            props_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS artifacts (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            path TEXT NOT NULL,
            run_dir TEXT NOT NULL DEFAULT '',
            snapshot_id TEXT NOT NULL,
            sha256 TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            props_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_snapshots_target
            ON snapshots(target_path, created_at);
        CREATE INDEX IF NOT EXISTS idx_nodes_kind_snapshot
            ON nodes(kind, snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_nodes_file
            ON nodes(file);
        CREATE INDEX IF NOT EXISTS idx_edges_kind_snapshot
            ON edges(kind, snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_edges_src
            ON edges(src_id);
        CREATE INDEX IF NOT EXISTS idx_edges_dst
            ON edges(dst_id);
        """
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
        ("schema_version", str(SCHEMA_VERSION)),
    )
