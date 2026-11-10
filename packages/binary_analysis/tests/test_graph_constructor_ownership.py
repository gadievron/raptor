"""Native private SQLite constructor refusal and cleanup-error precedence."""
import sqlite3
from types import SimpleNamespace

import pytest

from packages.binary_analysis import graph_store as consumer


@pytest.fixture
def graph_io(tmp_path, monkeypatch):
    path = tmp_path / "owned.sqlite"
    seed = sqlite3.connect(path)
    try:
        seed.execute("CREATE TABLE retained_sentinel(value TEXT)")
        seed.execute("INSERT INTO retained_sentinel VALUES ('keep')")
        seed.execute(f"PRAGMA user_version={consumer.SCHEMA_VERSION + 1}")
        seed.commit()
    finally:
        seed.close()
    state = {"path": path, "connections": [], "closes": 0,
             "cleanup": None, "primary": None}
    native_migrate = consumer._migrate

    class Connection(sqlite3.Connection):
        def close(self):
            sqlite3.Connection.close(self)
            state["closes"] += 1
            if state["cleanup"] is not None:
                raise state["cleanup"]

    def connected(*args, **kwargs):
        connection = sqlite3.connect(*args, **kwargs, factory=Connection)
        state["connections"].append(connection)
        return connection

    def migrated(connection):
        native_migrate(connection)
        if state["primary"] is not None:
            raise state["primary"]

    monkeypatch.setattr(consumer, "sqlite3", SimpleNamespace(
        **{**vars(sqlite3), "connect": connected}))
    monkeypatch.setattr(consumer, "_migrate", migrated)
    try:
        yield state
    finally:
        for connection in state["connections"]:
            sqlite3.Connection.close(connection)


def test_future_schema_refusal_survives_consumed_connection_close(graph_io):
    graph_io["cleanup"] = sqlite3.OperationalError("after native connection close")
    with pytest.raises(RuntimeError, match="newer than this RAPTOR"):
        consumer.open_graph(graph_io["path"])
    assert graph_io["closes"] == 1
    with pytest.raises(sqlite3.ProgrammingError):
        graph_io["connections"][0].execute("SELECT 1")
    verify = sqlite3.connect(graph_io["path"])
    try:
        assert verify.execute("PRAGMA user_version").fetchone()[0] == consumer.SCHEMA_VERSION + 1
        assert verify.execute("SELECT value FROM retained_sentinel").fetchall() == [("keep",)]
    finally:
        verify.close()


def _set_version(graph_io, version):
    connection = sqlite3.connect(graph_io["path"])
    try:
        connection.execute(f"PRAGMA user_version={version}")
        connection.commit()
    finally:
        connection.close()


def _assert_retired(graph_io):
    assert graph_io["closes"] == 1
    assert len(graph_io["connections"]) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        graph_io["connections"][0].execute("SELECT 1")


@pytest.mark.parametrize("close_type", [None, KeyboardInterrupt, MemoryError])
def test_native_future_schema_guard_remains_primary(graph_io, close_type):
    if close_type is not None:
        graph_io["cleanup"] = close_type("after native connection close")
    with pytest.raises(RuntimeError, match="newer than this RAPTOR"):
        consumer.open_graph(graph_io["path"])
    _assert_retired(graph_io)
    verify = sqlite3.connect(graph_io["path"])
    try:
        assert verify.execute("PRAGMA user_version").fetchone()[0] == consumer.SCHEMA_VERSION + 1
        assert verify.execute("SELECT value FROM retained_sentinel").fetchall() == [("keep",)]
    finally:
        verify.close()


@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [sqlite3.OperationalError, KeyboardInterrupt])
def test_post_migration_failure_keeps_primary_and_retires_connection(
        graph_io, primary_type, close_type):
    _set_version(graph_io, 0)
    primary = primary_type("after actual native migration")
    graph_io["primary"] = primary
    graph_io["cleanup"] = close_type("after native connection close")
    with pytest.raises(primary_type) as raised:
        consumer.open_graph(graph_io["path"])
    assert raised.value is primary
    _assert_retired(graph_io)


def test_success_returns_live_native_connection(graph_io):
    _set_version(graph_io, 0)
    connection = consumer.open_graph(graph_io["path"])
    assert connection is graph_io["connections"][0]
    assert graph_io["closes"] == 0
    assert connection.execute("PRAGMA user_version").fetchone()[0] == consumer.SCHEMA_VERSION
    assert connection.execute("SELECT value FROM retained_sentinel").fetchall()[0][0] == "keep"
    connection.close()
    _assert_retired(graph_io)


@pytest.mark.parametrize("close_type", [sqlite3.OperationalError, KeyboardInterrupt])
def test_returned_connection_close_failure_stays_visible(graph_io, close_type):
    _set_version(graph_io, 0)
    connection = consumer.open_graph(graph_io["path"])
    assert graph_io["closes"] == 0
    cleanup = close_type("after caller-owned native close")
    graph_io["cleanup"] = cleanup
    with pytest.raises(close_type) as raised:
        connection.close()
    assert raised.value is cleanup
    _assert_retired(graph_io)
