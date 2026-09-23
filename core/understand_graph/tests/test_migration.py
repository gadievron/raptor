"""v1 -> v2 migration durability: transacted swap, direction-aware recovery.

The v1->v2 table swap used to run statement-at-a-time in autocommit
while the recovery sweep blindly DROPped any ``nodes_v1_tmp`` it found
next to a ``nodes`` table. An interrupt between the (autocommitted)
CREATE and the copy's commit — or a concurrent first-open at that
interleave point — left the tmp table holding the ONLY copy of every
legacy row, and the next open destroyed it silently. These tests pin
the survival of legacy rows through both windows.
"""

import sqlite3

import pytest

from core.understand_graph.store import open_graph

_V1_SCHEMA = """
    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE snapshots (id TEXT PRIMARY KEY, target_path TEXT NOT NULL,
        target_hash TEXT NOT NULL DEFAULT '', git_sha TEXT NOT NULL DEFAULT '',
        checklist_hash TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '',
        producer_run TEXT NOT NULL DEFAULT '', props_json TEXT NOT NULL DEFAULT '{}');
    CREATE TABLE nodes (id TEXT PRIMARY KEY, kind TEXT NOT NULL,
        stable_key TEXT NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT '',
        file TEXT NOT NULL DEFAULT '', line_start INTEGER, line_end INTEGER,
        snapshot_id TEXT NOT NULL, stale INTEGER NOT NULL DEFAULT 0,
        props_json TEXT NOT NULL DEFAULT '{}');
    CREATE TABLE edges (id TEXT PRIMARY KEY, src_id TEXT NOT NULL, dst_id TEXT NOT NULL,
        kind TEXT NOT NULL, confidence TEXT NOT NULL DEFAULT '',
        snapshot_id TEXT NOT NULL, stale INTEGER NOT NULL DEFAULT 0,
        evidence_json TEXT NOT NULL DEFAULT '{}', props_json TEXT NOT NULL DEFAULT '{}');
    CREATE TABLE artifacts (id TEXT PRIMARY KEY, kind TEXT NOT NULL, path TEXT NOT NULL,
        run_dir TEXT NOT NULL DEFAULT '', snapshot_id TEXT NOT NULL,
        sha256 TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '',
        props_json TEXT NOT NULL DEFAULT '{}');
    INSERT INTO snapshots (id, target_path) VALUES ('snap1', '/legacy/target');
    INSERT INTO nodes (id, kind, stable_key, name, snapshot_id) VALUES
        ('n1','entry_point','entry_point://EP-1','handle_request','snap1'),
        ('n2','sink','sink://SINK-1','system','snap1'),
        ('n3','unchecked_flow','unchecked_flow://FLOW-1','FLOW-1','snap1');
    INSERT INTO edges (id, src_id, dst_id, kind, snapshot_id) VALUES
        ('e1','n1','n2','REACHES','snap1');
    PRAGMA user_version=1;
"""

# The exact new-format nodes table _migrate_2 creates (replayed by the
# crash/concurrency arms to reproduce a mid-swap state byte-for-byte).
_NEW_NODES = """CREATE TABLE nodes (id TEXT PRIMARY KEY, kind TEXT NOT NULL,
    stable_key TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', file TEXT NOT NULL DEFAULT '',
    line_start INTEGER, line_end INTEGER, snapshot_id TEXT NOT NULL,
    stale INTEGER NOT NULL DEFAULT 0, props_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE)"""

_COPY = """INSERT OR IGNORE INTO nodes SELECT id, kind, stable_key, name, file,
    line_start, line_end, snapshot_id, stale, props_json FROM nodes_v1_tmp"""


def _make_v1_db(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(_V1_SCHEMA)
    conn.commit()
    conn.close()


def _node_count(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT COUNT(*) AS c FROM nodes").fetchone()["c"]
    finally:
        conn.close()


def _tables(path):
    conn = sqlite3.connect(path)
    try:
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


def test_v1_migration_preserves_rows(tmp_path):
    db = tmp_path / "raptor.graph.sqlite"
    _make_v1_db(db)
    conn = open_graph(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] == 3
        assert conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0] == 1
        assert conn.execute("PRAGMA user_version").fetchone()[0] >= 3
    finally:
        conn.close()
    assert "nodes_v1_tmp" not in _tables(db)


def test_crash_mid_swap_recovery_restores_legacy_rows(tmp_path):
    """Kill between the autocommitted CREATE and the copy's commit:
    ``nodes`` is empty and ``nodes_v1_tmp`` holds every row. The next
    open must RESTORE from the tmp table, never drop the only copy."""
    db = tmp_path / "raptor.graph.sqlite"
    _make_v1_db(db)

    crashed = sqlite3.connect(db)
    crashed.execute("PRAGMA legacy_alter_table=ON")
    crashed.execute("ALTER TABLE nodes RENAME TO nodes_v1_tmp")
    crashed.execute(_NEW_NODES)
    crashed.execute(_COPY)
    # close() without commit == the process died: the copy's implicit
    # transaction rolls back, the DDL above already autocommitted.
    crashed.close()

    assert _node_count(db) == 0  # the mid-crash state under test

    conn = open_graph(db)
    conn.close()
    assert _node_count(db) == 3
    assert "nodes_v1_tmp" not in _tables(db)


def test_concurrent_first_open_mid_swap_preserves_rows(tmp_path):
    """Process A replays the swap's opening statements (autocommitting
    DDL); process B runs the REAL open_graph() at the interleave
    point. B's recovery must leave all three legacy rows alive."""
    db = tmp_path / "raptor.graph.sqlite"
    _make_v1_db(db)

    a = sqlite3.connect(db)
    a.execute("PRAGMA busy_timeout=5000")
    a.execute("PRAGMA legacy_alter_table=ON")
    a.execute("ALTER TABLE nodes RENAME TO nodes_v1_tmp")
    a.execute(_NEW_NODES)

    b = open_graph(db)
    b.close()

    # A is a raced/crashed migrator: its copy may fail (the recovery
    # already consumed the tmp table) — that is fine as long as the
    # rows survived in the real store.
    try:
        a.execute(_COPY)
        a.commit()
    except sqlite3.OperationalError:
        pass
    a.close()

    assert _node_count(db) == 3


def test_completed_swap_recovery_drops_leftover_tmp(tmp_path):
    """Interrupt AFTER the copy committed but before the tmp DROP: the
    recovery direction check sees the copy landed and drops the tmp
    without duplicating or losing rows."""
    db = tmp_path / "raptor.graph.sqlite"
    _make_v1_db(db)

    c = sqlite3.connect(db)
    c.execute("PRAGMA legacy_alter_table=ON")
    c.execute("ALTER TABLE nodes RENAME TO nodes_v1_tmp")
    c.execute(_NEW_NODES)
    c.execute(_COPY)
    c.commit()  # copy landed; DROP never ran
    c.close()

    conn = open_graph(db)
    conn.close()
    assert _node_count(db) == 3
    assert "nodes_v1_tmp" not in _tables(db)


def test_newer_schema_raises_typed_error(tmp_path):
    """A store written by a newer RAPTOR raises the typed schema error
    (a RuntimeError subclass) — never a destructive downgrade."""
    from core.understand_graph.store import GraphSchemaNewerError

    db = tmp_path / "raptor.graph.sqlite"
    conn = open_graph(db)
    conn.close()
    raw = sqlite3.connect(db)
    raw.execute("PRAGMA user_version=99")
    raw.commit()
    raw.close()

    with pytest.raises(GraphSchemaNewerError):
        open_graph(db)
    # The store itself is untouched.
    assert db.exists()
