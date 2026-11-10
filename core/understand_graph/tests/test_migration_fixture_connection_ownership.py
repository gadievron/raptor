"""Reopened migration fixture connections retire before their write holder."""

import sqlite3
from contextlib import closing
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_store_guard as native


def _exercise(tmp_path, error, after):
    records = []
    closed = []
    failure = error("owned migration fault") if error and error is not sqlite3.OperationalError else None

    class Connection(sqlite3.Connection):
        def close(self):
            super().close()
            closed.append(self.owner_index)

    def connected(path):
        connection = sqlite3.connect(path, factory=Connection)
        connection.owner_index = len(records)
        records.append(connection)
        return connection

    def abort(connection):
        if error is sqlite3.OperationalError:
            connection.execute("SELECT * FROM fixture_missing_table")
        raise failure

    def migrate(connection):
        if error and not after:
            abort(connection)
        native.migrate(connection)
        if error:
            abort(connection)

    method = native.test_migrate_is_write_free_when_schema_current
    body = FunctionType(method.__code__, {
        **method.__globals__,
        "migrate": migrate,
        "sqlite3": SimpleNamespace(connect=connected, Row=sqlite3.Row),
    })
    try:
        if error:
            match = "fixture_missing_table" if error is sqlite3.OperationalError else "owned migration fault"
            with pytest.raises(error, match=match) as caught:
                body(tmp_path)
            if failure is not None:
                assert caught.value is failure
        else:
            body(tmp_path)
        assert len(records) == 2
        assert closed == [1, 0]
        for connection in records:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                connection.execute("SELECT 1")
        with closing(sqlite3.connect(tmp_path / "g.sqlite", timeout=0.1)) as probe:
            probe.execute("BEGIN IMMEDIATE")
            probe.rollback()
            assert probe.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] == 0
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit, sqlite3.OperationalError])
@pytest.mark.parametrize("after", [False, True])
def test_migration_faults_close_inner_before_outer(tmp_path, error, after):
    _exercise(tmp_path, error, after)


def test_native_write_free_migration_closes_both_connections(tmp_path):
    _exercise(tmp_path, None, True)
