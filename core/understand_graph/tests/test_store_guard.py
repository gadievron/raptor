"""Store guard tests: the graph is durable cross-run memory — only
genuine corruption may remove it, and read queries must not contend
for the write lock."""

from __future__ import annotations

import sqlite3

import core.understand_graph.store as store
from core.understand_graph.store import (
    migrate,
    open_graph,
    query_graph,
    remove_graph_db,
)


def _seed(db_path):
    conn = open_graph(db_path)
    conn.commit()
    conn.close()


def test_lock_contention_never_deletes_the_graph(tmp_path, monkeypatch):
    """A writer holding BEGIN IMMEDIATE (an in-flight ingest) must not
    cost the project its graph when a query lane collides with it."""
    db_path = tmp_path / "g.sqlite"
    _seed(db_path)
    monkeypatch.setattr(store, "_BUSY_TIMEOUT_MS", 5)
    monkeypatch.setattr(store, "_LOCK_RETRY_DELAY_S", 0.01)

    locker = sqlite3.connect(db_path)
    try:
        locker.execute("BEGIN IMMEDIATE")
        result = query_graph(
            db_path,
            lambda conn: conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],
        )
    finally:
        locker.rollback()
        locker.close()

    # The graph survives regardless of whether the read succeeded.
    assert db_path.exists()
    # And under WAL + write-free migrate, a pure read does not need
    # the write lock at all — the query succeeds despite the writer.
    assert result == 0


def test_bad_sql_from_a_caller_never_deletes_the_graph(tmp_path):
    """OperationalError('no such table') is a DatabaseError subclass;
    the old blanket guard unlinked the store for a caller bug."""
    db_path = tmp_path / "g.sqlite"
    _seed(db_path)
    result = query_graph(
        db_path, lambda conn: conn.execute("SELECT * FROM no_such_table"),
    )
    assert result is None
    assert db_path.exists()
    assert not list(tmp_path.glob("*.corrupt-*"))


def test_migrate_is_write_free_when_schema_current(tmp_path):
    """Re-opening an up-to-date graph must not write: a second
    connection can open it while a writer holds the write lock."""
    db_path = tmp_path / "g.sqlite"
    _seed(db_path)

    locker = sqlite3.connect(db_path)
    try:
        locker.execute("BEGIN IMMEDIATE")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5")
        migrate(conn)  # raises "database is locked" if it writes
        conn.close()
    finally:
        locker.rollback()
        locker.close()


def test_quarantine_moves_wal_sidecars_aside(tmp_path):
    db_path = tmp_path / "g.sqlite"
    db_path.write_bytes(b"garbage, not sqlite")
    (tmp_path / "g.sqlite-wal").write_bytes(b"wal")
    (tmp_path / "g.sqlite-shm").write_bytes(b"shm")

    result = query_graph(db_path, lambda conn: conn.execute("SELECT 1"))
    assert result is None
    assert not db_path.exists()
    # No stale sidecars left beside the (future recreated) DB name.
    assert not (tmp_path / "g.sqlite-wal").exists()
    assert not (tmp_path / "g.sqlite-shm").exists()
    assert list(tmp_path.glob("g.sqlite.corrupt-*"))


def test_remove_graph_db_removes_sidecars(tmp_path):
    db_path = tmp_path / "g.sqlite"
    _seed(db_path)
    for suffix in ("-wal", "-shm"):
        sidecar = tmp_path / f"g.sqlite{suffix}"
        if not sidecar.exists():
            sidecar.write_bytes(b"x")
    remove_graph_db(db_path)
    assert not db_path.exists()
    assert not (tmp_path / "g.sqlite-wal").exists()
    assert not (tmp_path / "g.sqlite-shm").exists()


def test_caller_identifier_echo_is_not_corruption(tmp_path):
    """'no such table: malformed' echoes a CALLER identifier inside an
    OperationalError — substring matching would quarantine a healthy
    store for it. Corruption detection anchors on sqlite error codes
    (full fixed phrases as fallback)."""
    db_path = tmp_path / "g.sqlite"
    _seed(db_path)
    result = query_graph(
        db_path, lambda conn: conn.execute("SELECT * FROM malformed"),
    )
    assert result is None
    assert db_path.exists()
    assert not list(tmp_path.glob("*.corrupt-*"))
