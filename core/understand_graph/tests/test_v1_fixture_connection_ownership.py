"""Legacy schema fixture scripts own their native SQLite connection."""

import sqlite3
from contextlib import closing
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_migration as native


def _exercise(tmp_path, error=None, after=True, table=None):
    records = []
    closed = []
    failure = error("owned legacy script fault") if error else None

    class Connection(sqlite3.Connection):
        def executescript(self, script):
            assert script == native._V1_SCHEMA
            if error and not after:
                raise failure
            result = super().executescript(script)
            if error:
                raise failure
            return result

        def close(self):
            super().close()
            closed.append(self)

    def connected(path):
        connection = sqlite3.connect(path, factory=Connection)
        records.append(connection)
        if table:
            connection.set_authorizer(
                lambda action, arg, *rest: sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_CREATE_TABLE and arg == table else sqlite3.SQLITE_OK,
            )
        return connection

    path = tmp_path / "v1.sqlite"
    body = FunctionType(native._make_v1_db.__code__, {
        **native._make_v1_db.__globals__, "sqlite3": SimpleNamespace(connect=connected),
    })
    expected = error or (sqlite3.DatabaseError if table else None)
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if table else "owned legacy script fault") as caught:
                body(path)
            if failure is not None:
                assert caught.value is failure
        else:
            body(path)
        assert len(records) == 1
        assert closed == records
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            records[0].execute("SELECT 1")
        if not expected:
            with closing(sqlite3.connect(path)) as reader:
                assert reader.execute("PRAGMA user_version").fetchone()[0] == 1
                assert reader.execute("SELECT kind,src_id,dst_id FROM edges").fetchall() == [("REACHES", "n1", "n2")]
                assert reader.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] == 3
                columns = {row[1] for row in reader.execute("PRAGMA table_info(edges)")}
                assert "provenance" not in columns and "integrity" not in columns
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_script_faults_retire_connection(tmp_path, error, after):
    _exercise(tmp_path, error, after)


@pytest.mark.parametrize("table", ["metadata", "nodes"])
def test_native_schema_authorization_error_retires_connection(tmp_path, table):
    _exercise(tmp_path, table=table)


def test_native_v1_schema_and_rows_survive_cleanup(tmp_path):
    _exercise(tmp_path)
