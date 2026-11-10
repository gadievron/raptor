"""Private SQLite context cleanup; transaction calls retain their original policy."""
import sqlite3
from types import SimpleNamespace

import pytest

from packages.binary_analysis import graph_store as module


@pytest.fixture
def transaction_io(tmp_path, monkeypatch):
    path = tmp_path / "owned.sqlite"
    setup = sqlite3.connect(path)
    try:
        setup.execute("CREATE TABLE owned_probe(value TEXT)")
        setup.commit()
    finally:
        setup.close()
    state = {"path": path, "connection": None, "armed": False,
             "commits": 0, "rollbacks": 0, "closes": 0,
             "commit_error": None, "rollback_error": None, "close_error": None}
    native_open = module.open_graph

    class Connection(sqlite3.Connection):
        def commit(self):
            sqlite3.Connection.commit(self)
            if state["armed"]:
                state["commits"] += 1
                if state["commit_error"] is not None:
                    raise state["commit_error"]

        def rollback(self):
            sqlite3.Connection.rollback(self)
            if state["armed"]:
                state["rollbacks"] += 1
                if state["rollback_error"] is not None:
                    raise state["rollback_error"]

        def close(self):
            sqlite3.Connection.close(self)
            if state["armed"]:
                state["closes"] += 1
                if state["close_error"] is not None:
                    raise state["close_error"]

    def connected(*args, **kwargs):
        connection = sqlite3.connect(*args, **kwargs, factory=Connection)
        state["connection"] = connection
        return connection

    def opened(path):
        connection = native_open(path)
        state["armed"] = True
        return connection

    monkeypatch.setattr(module, "sqlite3", SimpleNamespace(**{**vars(sqlite3), "connect": connected}))
    monkeypatch.setattr(module, "open_graph", opened)
    try:
        yield state
    finally:
        if state["connection"] is not None:
            sqlite3.Connection.close(state["connection"])


def _assert_retired(state, *, commits, rollbacks, rows):
    assert (state["commits"], state["rollbacks"], state["closes"]) == (commits, rollbacks, 1)
    with pytest.raises(sqlite3.ProgrammingError):
        state["connection"].execute("SELECT 1")
    verify = sqlite3.connect(state["path"])
    try:
        assert verify.execute("SELECT value FROM owned_probe").fetchall() == rows
    finally:
        verify.close()


def test_body_error_survives_consumed_connection_close(transaction_io):
    primary = RuntimeError("after native insert")
    transaction_io["close_error"] = sqlite3.OperationalError("after native close")
    with pytest.raises(RuntimeError) as raised:
        with module.graph_connection(transaction_io["path"]) as connection:
            connection.execute("INSERT INTO owned_probe VALUES ('plain')")
            raise primary
    assert raised.value is primary
    _assert_retired(transaction_io, commits=0, rollbacks=1, rows=[])


@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [sqlite3.OperationalError, KeyboardInterrupt])
def test_body_error_preserves_existing_rollback_policy(transaction_io, primary_type, close_type):
    primary = primary_type("after native insert")
    transaction_io["close_error"] = close_type("after native close")
    with pytest.raises(primary_type) as raised:
        with module.graph_connection(transaction_io["path"]) as connection:
            connection.execute("INSERT INTO owned_probe VALUES ('plain')")
            raise primary
    assert raised.value is primary
    _assert_retired(transaction_io, commits=0, rollbacks=int(isinstance(primary, Exception)), rows=[])


@pytest.mark.parametrize("commit_type", [sqlite3.OperationalError, KeyboardInterrupt])
@pytest.mark.parametrize("close_type", [sqlite3.OperationalError, KeyboardInterrupt])
def test_commit_error_keeps_identity_and_original_rollback_dispatch(transaction_io, commit_type, close_type):
    primary = commit_type("after native commit")
    transaction_io.update(commit_error=primary, close_error=close_type("after native close"))
    with pytest.raises(commit_type) as raised:
        with module.graph_connection(transaction_io["path"]) as connection:
            connection.execute("INSERT INTO owned_probe VALUES ('plain')")
    assert raised.value is primary
    # Faults follow native commit: the committed row is deliberately retained.
    _assert_retired(transaction_io, commits=1, rollbacks=int(isinstance(primary, Exception)), rows=[("plain",)])


@pytest.mark.parametrize("rollback_type", [sqlite3.OperationalError, KeyboardInterrupt])
def test_existing_rollback_error_priority_is_retained(transaction_io, rollback_type):
    rollback_error = rollback_type("after native rollback")
    transaction_io.update(rollback_error=rollback_error, close_error=MemoryError("after native close"))
    with pytest.raises(rollback_type) as raised:
        with module.graph_connection(transaction_io["path"]) as connection:
            connection.execute("INSERT INTO owned_probe VALUES ('plain')")
            raise ValueError("body error precedes existing rollback-error policy")
    assert raised.value is rollback_error
    _assert_retired(transaction_io, commits=0, rollbacks=1, rows=[])


@pytest.mark.parametrize("close_type", [sqlite3.OperationalError, KeyboardInterrupt, MemoryError])
def test_fresh_close_error_after_commit_stays_visible(transaction_io, close_type):
    cleanup = close_type("after native close")
    transaction_io["close_error"] = cleanup
    with pytest.raises(close_type) as raised:
        with module.graph_connection(transaction_io["path"]) as connection:
            connection.execute("INSERT INTO owned_probe VALUES ('plain')")
    assert raised.value is cleanup
    _assert_retired(transaction_io, commits=1, rollbacks=0, rows=[("plain",)])


def test_native_success_commits_then_closes(transaction_io):
    with module.graph_connection(transaction_io["path"]) as connection:
        connection.execute("INSERT INTO owned_probe VALUES ('plain')")
    _assert_retired(transaction_io, commits=1, rollbacks=0, rows=[("plain",)])


def test_native_sql_refusal_remains_primary(transaction_io):
    transaction_io["close_error"] = MemoryError("after native close")
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        with module.graph_connection(transaction_io["path"]) as connection:
            connection.execute("SELECT * FROM absent_owned_probe")
    _assert_retired(transaction_io, commits=0, rollbacks=1, rows=[])
