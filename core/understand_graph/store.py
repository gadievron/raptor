"""SQLite store and migrations for RAPTOR's /understand graph."""

from __future__ import annotations

import os
import sqlite3
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from .schema import SCHEMA_VERSION

GRAPH_FILENAME = "raptor.graph.sqlite"

# Per-connection write-lock wait before sqlite raises "database is
# locked". Module constant so contention tests can shrink it.
_BUSY_TIMEOUT_MS = 5000

# Errors that mean the FILE is damaged — only these earn quarantine.
# Everything else (locks, transient I/O, bad SQL from a caller) must
# never remove the store: the graph is the project's durable
# cross-run memory, and concurrent opens are routine (ingest during
# /agentic vs. /project status from another session). Primary
# discriminator is the sqlite extended error code; the FULL fixed
# message phrases are a fallback for exceptions without one. Short
# fragments are not safe here: "no such table: malformed" (a caller's
# identifier echoed in an OperationalError) must not read as
# corruption.
_CORRUPTION_SQLITE_CODES = frozenset({
    getattr(sqlite3, "SQLITE_CORRUPT", 11),
    getattr(sqlite3, "SQLITE_NOTADB", 26),
})
_CORRUPTION_SIGNATURES = (
    "database disk image is malformed",
    "file is not a database",
    "file is encrypted or is not a database",
)


def _is_corruption(exc: sqlite3.DatabaseError) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    if code is not None:
        # Compare primary result codes: extended codes carry the
        # primary in their low byte (e.g. SQLITE_CORRUPT_INDEX).
        return (code & 0xFF) in _CORRUPTION_SQLITE_CODES
    message = str(exc).lower()
    return any(sig in message for sig in _CORRUPTION_SIGNATURES)

# Lock-contention fragments worth a brief retry before degrading.
_LOCK_SIGNATURES = ("database is locked", "database is busy")
_LOCK_RETRIES = 3
_LOCK_RETRY_DELAY_S = 0.25


def graph_sidecar_paths(path: Path) -> list[Path]:
    """The WAL-mode sidecar files that accompany a graph DB."""
    path = Path(path)
    return [path.with_name(path.name + suffix) for suffix in ("-wal", "-shm")]


def remove_graph_db(path: Path) -> bool:
    """Delete a graph DB together with its WAL sidecars.

    Removing only the main file leaves a stale ``-wal`` next to a
    recreated same-name DB; every deletion site routes through here.
    Returns False when any victim could not be removed, so callers
    can report the failure instead of claiming success.
    """
    path = Path(path)
    ok = True
    for victim in [path, *graph_sidecar_paths(path)]:
        try:
            victim.unlink(missing_ok=True)
        except OSError:
            ok = False
    return ok


def _quarantine_corrupt_graph(path: Path, exc: Exception) -> None:
    """Move a genuinely corrupt graph aside (never silently unlink).

    The DB and its sidecars are renamed to ``<name>.corrupt-<ts>``
    (sidecar suffixes preserved so sqlite tooling can still open the
    quarantined copy); rename failure degrades to sidecar-aware
    deletion.
    """
    path = Path(path)
    ts = time.strftime("%Y%m%d-%H%M%S")
    # pid suffix: two corruption events in the same second must not
    # rename over each other's quarantine.
    quarantine = path.with_name(path.name + f".corrupt-{ts}-{os.getpid()}")
    print(
        f"graph: corrupt ({exc}), quarantining {path.name} -> {quarantine.name}",
        file=sys.stderr,
    )
    try:
        path.rename(quarantine)
        for sidecar in graph_sidecar_paths(path):
            if sidecar.exists():
                sidecar.rename(quarantine.parent / sidecar.name.replace(
                    path.name, quarantine.name, 1))
    except OSError:
        if not remove_graph_db(path):
            # Per the helper's contract: report the failure instead of
            # claiming success — a corrupt DB that survives quarantine
            # keeps crashing every consumer until an operator removes it.
            print(
                f"graph: could not quarantine or remove corrupt {path.name}",
                file=sys.stderr,
            )


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
    conn.execute(f"PRAGMA busy_timeout={int(_BUSY_TIMEOUT_MS)}")
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


#: What an ingest producer contains to a "skipped" ingest — run-dir
#: artifacts are producer-written but live beside scanned-tree output,
#: so a junk shape must cost the ingest, never the caller.
#: AttributeError is in the tuple because unvalidated shapes reach
#: ``.get()`` calls (a list-shaped checklist.json crashed the primary
#: understand ingest through exactly that hole).
INGEST_SKIP_EXCEPTIONS = (
    sqlite3.Error, AttributeError, KeyError, TypeError, ValueError,
)


@contextmanager
def graph_write_txn(path: Path) -> Iterator[sqlite3.Connection]:
    """One immediate write transaction for an ingest producer.

    BEGIN IMMEDIATE .. COMMIT, rollback-and-re-raise on any failure,
    connection always closed. The producers used to hand-roll this
    envelope per function — and the one that predated the pattern
    (ingest_run) drifted without any of it.
    """
    conn = open_graph(path)
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
    finally:
        conn.close()


def query_graph(path: Path, fn, *args, **kwargs):
    """Run a read query with a narrow corruption guard.

    Only genuine file corruption (sqlite's malformed / not-a-database
    errors) quarantines the graph; the query then returns None and
    consumers degrade to 'no graph'. TRANSIENT errors must never
    delete the store: ``sqlite3.OperationalError`` — "database is
    locked" above all, which concurrent ingest makes routine — is a
    ``DatabaseError`` subclass, and the old blanket guard unlinked the
    project's accumulated cross-run memory on the first 5s lock
    collision (or even on a caller's bad SQL). Lock contention gets a
    brief retry, then None with the file untouched.
    """
    if not Path(path).exists():
        return None
    for attempt in range(_LOCK_RETRIES + 1):
        try:
            with graph_connection(path) as conn:
                return fn(conn, *args, **kwargs)
        except GraphSchemaNewerError as exc:
            # From-the-future store: degrade (report + None), NEVER
            # quarantine — the file is not corrupt, and the newer
            # RAPTOR that wrote it can still read it.
            print(
                f"graph: {exc}; keeping {Path(path).name}",
                file=sys.stderr,
            )
            return None
        except sqlite3.DatabaseError as exc:
            if _is_corruption(exc):
                _quarantine_corrupt_graph(Path(path), exc)
                return None
            message = str(exc).lower()
            if (any(sig in message for sig in _LOCK_SIGNATURES)
                    and attempt < _LOCK_RETRIES):
                time.sleep(_LOCK_RETRY_DELAY_S * (attempt + 1))
                continue
            print(
                f"graph: query failed ({exc}); keeping {Path(path).name}",
                file=sys.stderr,
            )
            return None
    return None


class GraphSchemaNewerError(RuntimeError):
    """The store was written by a newer RAPTOR's schema.

    RuntimeError subclass so pre-existing broad handlers keep working;
    typed so the read guard can degrade (report + None) instead of
    crashing every consumer — and never quarantine: the file is not
    corrupt, it is from the future.
    """


def migrate(conn: sqlite3.Connection) -> None:
    current = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if current == SCHEMA_VERSION:
        # Up to date: return before ANY write. Every open_graph() runs
        # migrate(), so an unconditional PRAGMA user_version= +
        # metadata INSERT made even pure read queries contend for the
        # write lock against in-flight ingests.
        return
    if current > SCHEMA_VERSION:
        raise GraphSchemaNewerError(
            f"graph schema version {current} is newer than this RAPTOR ({SCHEMA_VERSION})"
        )
    # The whole mutating path runs in ONE immediate transaction and
    # commits here — never relying on the caller. The pre-fix
    # statement-at-a-time swap autocommitted its DDL while the row
    # copy rode an implicit transaction, so an interrupt (or a caller
    # that closed without committing) left ``nodes`` empty with
    # ``nodes_v1_tmp`` holding the only copy of every legacy row.
    # FK enforcement is toggled OUTSIDE the transaction — PRAGMA
    # foreign_keys is a no-op inside one.
    conn.execute("PRAGMA foreign_keys=OFF")
    prev_isolation = conn.isolation_level
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            # Re-read under the write lock: a concurrent first-open
            # may have migrated while we waited (the check-then-write
            # window that made two pre-v3 openers race the v3 ALTER
            # into a "duplicate column name" crash).
            current = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if current > SCHEMA_VERSION:
                raise GraphSchemaNewerError(
                    f"graph schema version {current} is newer than this RAPTOR ({SCHEMA_VERSION})"
                )
            if current < SCHEMA_VERSION:
                if current < 1:
                    _migrate_1(conn)
                if current < 2:
                    _migrate_2(conn)
                if current < 3:
                    _migrate_3(conn)
                conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                conn.execute(
                    "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
                    ("schema_version", str(SCHEMA_VERSION)),
                )
            conn.execute("COMMIT")
        except BaseException:
            # All-or-nothing: the pre-migration store stays intact.
            # Corruption-class failures still quarantine downstream
            # (query_graph); everything else leaves the file alone.
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
    finally:
        conn.isolation_level = prev_isolation
        try:
            conn.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error:
            pass


def _migrate_1(conn: sqlite3.Connection) -> None:
    # Individual execute() calls, never executescript(): executescript
    # COMMITs any pending transaction first, which would tear the
    # all-or-nothing migration transaction open around it.
    _execute_statements(
        conn,
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
            stable_key TEXT NOT NULL,
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
        CREATE INDEX IF NOT EXISTS idx_nodes_stable_snapshot
            ON nodes(stable_key, snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_nodes_file
            ON nodes(file);
        CREATE INDEX IF NOT EXISTS idx_edges_kind_snapshot
            ON edges(kind, snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_edges_src
            ON edges(src_id);
        CREATE INDEX IF NOT EXISTS idx_edges_dst
            ON edges(dst_id);
        """,
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
        ("schema_version", "1"),
    )


def _execute_statements(conn: sqlite3.Connection, script: str) -> None:
    """Run a ';'-separated DDL block one execute() at a time (the
    statements here contain no literal semicolons)."""
    for statement in script.split(";"):
        if statement.strip():
            conn.execute(statement)


def _migrate_2(conn: sqlite3.Connection) -> None:
    """Make node rows snapshot-scoped so graph diffs can compare history.

    v1 used ``stable_key UNIQUE`` and updated the same node row on each ingest.
    That worked as memory, but erased older snapshots' node membership. v2 keeps
    stable_key for comparison while allowing one row per snapshot.
    """
    _recover_interrupted_v2_migration(conn)

    cols = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(nodes)").fetchall()
    }
    if "stable_key" not in cols:
        return

    indexes = conn.execute("PRAGMA index_list(nodes)").fetchall()
    has_unique_stable = False
    for row in indexes:
        if not bool(row["unique"]):
            continue
        index_cols = {
            info["name"]
            for info in conn.execute(f"PRAGMA index_info({row['name']})").fetchall()
        }
        if index_cols == {"stable_key"}:
            has_unique_stable = True
            break
    if not has_unique_stable:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nodes_stable_snapshot ON nodes(stable_key, snapshot_id)"
        )
        return

    nodes_old = "nodes_v1_tmp"
    edges_old = "edges_v1_tmp"

    # FK enforcement is already off: migrate() toggles it outside the
    # migration transaction (PRAGMA foreign_keys is a no-op inside one).
    conn.execute("PRAGMA legacy_alter_table=ON")
    conn.execute(f"ALTER TABLE nodes RENAME TO {nodes_old}")
    conn.execute(
        """
        CREATE TABLE nodes (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            stable_key TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            file TEXT NOT NULL DEFAULT '',
            line_start INTEGER,
            line_end INTEGER,
            snapshot_id TEXT NOT NULL,
            stale INTEGER NOT NULL DEFAULT 0,
            props_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        f"""
        INSERT OR IGNORE INTO nodes
        (id, kind, stable_key, name, file, line_start, line_end, snapshot_id, stale, props_json)
        SELECT id, kind, stable_key, name, file, line_start, line_end, snapshot_id, stale, props_json
        FROM {nodes_old}
        """
    )
    conn.execute(f"ALTER TABLE edges RENAME TO {edges_old}")
    conn.execute(
        """
        CREATE TABLE edges (
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
        )
        """
    )
    conn.execute(
        f"""
        INSERT OR IGNORE INTO edges
        (id, src_id, dst_id, kind, confidence, snapshot_id, stale, evidence_json, props_json)
        SELECT id, src_id, dst_id, kind, confidence, snapshot_id, stale, evidence_json, props_json
        FROM {edges_old}
        """
    )
    conn.execute(f"DROP TABLE {edges_old}")
    conn.execute(f"DROP TABLE {nodes_old}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_kind_snapshot ON nodes(kind, snapshot_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_file ON nodes(file)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_stable_snapshot ON nodes(stable_key, snapshot_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_kind_snapshot ON edges(kind, snapshot_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst_id)")
    conn.execute("PRAGMA legacy_alter_table=OFF")


_V2_COPY_COLUMNS = {
    "nodes": ("id, kind, stable_key, name, file, line_start, line_end, "
              "snapshot_id, stale, props_json"),
    "edges": ("id, src_id, dst_id, kind, confidence, snapshot_id, stale, "
              "evidence_json, props_json"),
}


def _recover_interrupted_v2_migration(conn: sqlite3.Connection) -> None:
    """Direction-aware sweep for a torn v1->v2 table swap.

    An interrupted swap can leave the ``*_v1_tmp`` table holding the
    ONLY copy of every legacy row (rename + CREATE autocommitted, the
    row copy rolled back). The pre-fix sweep DROPped the tmp whenever
    the new table also existed — destroying the store on the very open
    that should have healed it. Recovery now re-copies the tmp rows
    into the live table first (``INSERT OR IGNORE`` — a no-op when the
    copy had already landed) and only then drops the tmp. Runs inside
    migrate()'s transaction, so recovery itself is all-or-nothing.
    """
    tables = {
        row["name"]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    for current, legacy_names in (
        ("nodes", ("nodes_v1_tmp", "nodes_v1")),
        ("edges", ("edges_v1_tmp", "edges_v1")),
    ):
        for old_name in legacy_names:
            if old_name not in tables:
                continue
            if current not in tables:
                conn.execute(f"ALTER TABLE [{old_name}] RENAME TO {current}")
                tables.add(current)
                continue
            cols = _V2_COPY_COLUMNS[current]
            conn.execute(
                f"INSERT OR IGNORE INTO {current} ({cols}) "
                f"SELECT {cols} FROM [{old_name}]"  # noqa: S608 — identifiers are code constants
            )
            conn.execute(f"DROP TABLE [{old_name}]")


def _migrate_3(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_nodes_snap_kind_stale "
        "ON nodes(snapshot_id, kind, stale)"
    )
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(snapshots)").fetchall()}
    if "producer" not in cols:
        conn.execute(
            "ALTER TABLE snapshots ADD COLUMN producer TEXT NOT NULL DEFAULT 'understand'"
        )
