"""Owned synthetic metadata SQLite only, without repository or analysis actions."""
from contextlib import closing
import sqlite3
import sys
from types import SimpleNamespace

import pytest

from core.dataflow import cvefix_loader as module
from core.dataflow.tests.test_cvefix_loader import _make_db


@pytest.fixture
def connection_io(tmp_path, monkeypatch):
    path = tmp_path / "owned?#.sqlite"
    _make_db(path)
    state = {"path": path, "connections": [], "closes": 0, "fetches": 0,
             "fetch_error": None, "close_error": None, "primary": None,
             "conversions": 0, "before": path.read_bytes()}
    native_parent = module._single_parent

    class Cursor(sqlite3.Cursor):
        def fetchall(self):
            rows = super().fetchall()
            state["fetches"] += 1
            if state["fetch_error"] is not None:
                raise state["fetch_error"]
            return rows

    class Connection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.lstrip().startswith("SELECT DISTINCT f.cve_id"):
                return self.cursor(factory=Cursor).execute(sql, parameters)
            return super().execute(sql, parameters)

        def close(self):
            state["primary"] = sys.exc_info()[1]
            super().close()
            state["closes"] += 1
            if state["close_error"] is not None:
                raise state["close_error"]

    def connect(*args, **kwargs):
        assert args == (path.resolve().as_uri() + "?mode=ro",)
        assert kwargs == {"uri": True}
        connection = sqlite3.connect(*args, **kwargs, factory=Connection)
        state["connections"].append(connection)
        try:
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                connection.execute("CREATE TABLE forbidden_write(value TEXT)")
        except BaseException:
            sqlite3.Connection.close(connection)
            raise
        return connection

    def parent(value):
        state["conversions"] += 1
        assert state["closes"] == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            sqlite3.Connection.execute(state["connections"][0], "SELECT 1")
        return native_parent(value)

    monkeypatch.setattr(module, "sqlite3", SimpleNamespace(connect=connect))
    monkeypatch.setattr(module, "_single_parent", parent)
    try:
        yield state
    finally:
        for connection in state["connections"]:
            sqlite3.Connection.close(connection)


def _missing_table(state):
    with closing(sqlite3.connect(state["path"])) as connection:
        connection.execute("DROP TABLE fixes")
        connection.commit()
    state["before"] = state["path"].read_bytes()


def _assert_retired(state):
    assert state["closes"] == len(state["connections"]) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        state["connections"][0].execute("SELECT 1")
    assert state["path"].read_bytes() == state["before"]


def test_native_query_error_survives_secondary_close(connection_io):
    _missing_table(connection_io)
    connection_io["close_error"] = OSError("after native SQLite close")
    with pytest.raises(sqlite3.OperationalError, match="no such table") as raised:
        module.load_pairs(connection_io["path"])
    assert raised.value is connection_io["primary"]
    assert connection_io["fetches"] == connection_io["conversions"] == 0
    _assert_retired(connection_io)


@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, MemoryError])
def test_after_native_fetch_error_keeps_identity(connection_io, primary_type, close_type):
    primary = primary_type("after owned native query fetch")
    connection_io.update(fetch_error=primary, close_error=close_type("after native SQLite close"))
    with pytest.raises(primary_type) as raised:
        module.load_pairs(connection_io["path"])
    assert raised.value is primary
    assert connection_io["fetches"] == 1 and connection_io["conversions"] == 0
    _assert_retired(connection_io)


@pytest.mark.parametrize("close_type", [None, KeyboardInterrupt, MemoryError])
def test_native_query_refusal_identity_and_retirement(connection_io, close_type):
    _missing_table(connection_io)
    connection_io["close_error"] = close_type("after native SQLite close") if close_type else None
    with pytest.raises(sqlite3.OperationalError, match="no such table") as raised:
        module.load_pairs(connection_io["path"])
    assert raised.value is connection_io["primary"]
    assert connection_io["fetches"] == connection_io["conversions"] == 0
    _assert_retired(connection_io)


@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt, SystemExit])
def test_success_converts_only_after_close_and_keeps_fresh_errors(connection_io, close_type):
    cleanup = close_type("after native SQLite close") if close_type else None
    connection_io["close_error"] = cleanup
    if cleanup is None:
        pairs = module.load_pairs(connection_io["path"])
        assert pairs == [module.CveFixPair("CVE-GOOD", "CWE-89", "https://github.com/org/py-app", "Python", "fix1", "par1")]
        assert connection_io["conversions"] > 0
    else:
        with pytest.raises(close_type) as raised:
            module.load_pairs(connection_io["path"])
        assert raised.value is cleanup
        assert connection_io["conversions"] == 0
    assert connection_io["primary"] is None and connection_io["fetches"] == 1
    _assert_retired(connection_io)
