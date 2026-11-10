"""Future-schema fixture setup retires its raw version setter on errors."""

import sqlite3
from contextlib import closing
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_migration as native


def _exercise(tmp_path, error=None, after=True, deny=False):
    records = []
    closed = []
    opened_paths = []
    closed_before_refusal = []
    failure = error("owned version setter fault") if error else None

    class Connection(sqlite3.Connection):
        def execute(self, *args, **kwargs):
            self.calls += 1
            selected = error and self.calls == 1
            if selected and not after:
                raise failure
            result = super().execute(*args, **kwargs)
            if selected:
                raise failure
            return result

        def close(self):
            super().close()
            closed.append(self)

    def connected(path):
        connection = sqlite3.connect(path, factory=Connection)
        connection.calls = 0
        records.append(connection)
        if deny:
            connection.set_authorizer(
                lambda action, name, value, *rest: sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_PRAGMA and name == "user_version" and value is not None
                else sqlite3.SQLITE_OK,
            )
        return connection

    def opened(path):
        opened_paths.append(path)
        if records:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                sqlite3.Connection.execute(records[0], "SELECT 1")
            closed_before_refusal.append(True)
        return native.open_graph(path)

    method = native.test_newer_schema_raises_typed_error
    body = FunctionType(method.__code__, {
        **method.__globals__, "sqlite3": SimpleNamespace(connect=connected), "open_graph": opened,
    })
    expected = error or (sqlite3.DatabaseError if deny else None)
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if deny else "owned version setter fault") as caught:
                body(tmp_path)
            if failure is not None:
                assert caught.value is failure
        else:
            body(tmp_path)
        assert len(records) == 1
        assert closed == records
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            sqlite3.Connection.execute(records[0], "SELECT 1")
        assert len(opened_paths) == (1 if expected else 2)
        assert closed_before_refusal == ([] if expected else [True])
        if not expected:
            with closing(sqlite3.connect(tmp_path / "raptor.graph.sqlite")) as reader:
                assert reader.execute("PRAGMA user_version").fetchone()[0] == 99
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_version_write_faults_retire_fixture_connection(tmp_path, error, after):
    _exercise(tmp_path, error, after)


def test_native_version_write_refusal_retires_fixture_connection(tmp_path):
    _exercise(tmp_path, deny=True)


def test_native_typed_refusal_runs_after_fixture_retirement(tmp_path):
    _exercise(tmp_path)
