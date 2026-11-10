"""Native graph transaction holders retire even when rollback raises."""

import sqlite3
from contextlib import closing
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_store_guard as native

HOLDERS = ["test_lock_contention_never_deletes_the_graph", "test_migrate_is_write_free_when_schema_current"]


def _exercise(tmp_path, name, error=None, after=True, deny=False):
    records = []
    closed = []
    failure = error("owned holder rollback fault") if error else None
    before_options = (native.store._BUSY_TIMEOUT_MS, native.store._LOCK_RETRY_DELAY_S)

    class Connection(sqlite3.Connection):
        def rollback(self):
            selected = error and self.owner_index == 0
            if selected and not after:
                raise failure
            result = super().rollback()
            if selected:
                raise failure
            return result

        def close(self):
            super().close()
            closed.append(self.owner_index)

    def connected(path):
        connection = sqlite3.connect(path, factory=Connection)
        connection.owner_index = len(records)
        records.append(connection)
        if deny and connection.owner_index == 0:
            connection.set_authorizer(
                lambda action, arg, *rest: sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_TRANSACTION and arg == "ROLLBACK" else sqlite3.SQLITE_OK,
            )
        return connection

    method = getattr(native, name)
    body = FunctionType(method.__code__, {
        **method.__globals__, "sqlite3": SimpleNamespace(connect=connected, Row=sqlite3.Row),
    })
    expected = error or (sqlite3.DatabaseError if deny else None)
    try:
        with pytest.MonkeyPatch.context() as patch:
            def invoke():
                if name == "test_lock_contention_never_deletes_the_graph":
                    body(tmp_path, patch)
                else:
                    body(tmp_path)

            if expected:
                with pytest.raises(expected, match="not authorized" if deny else "owned holder rollback fault") as caught:
                    invoke()
                if failure is not None:
                    assert caught.value is failure
            else:
                invoke()
            count = 1 if name == "test_lock_contention_never_deletes_the_graph" else 2
            assert len(records) == count
            assert closed == ([0] if count == 1 else [1, 0])
            for connection in records:
                with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                    connection.execute("SELECT 1")
            with closing(sqlite3.connect(tmp_path / "g.sqlite", timeout=0.05)) as writer:
                writer.execute("BEGIN IMMEDIATE")
                writer.rollback()
                assert writer.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] == 0
        assert (native.store._BUSY_TIMEOUT_MS, native.store._LOCK_RETRY_DELAY_S) == before_options
    finally:
        for connection in records:
            try:
                connection.set_authorizer(None)
            except sqlite3.ProgrammingError:
                pass
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize("name", HOLDERS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_rollback_faults_retire_holder_and_release_writer(tmp_path, name, error, after):
    _exercise(tmp_path, name, error, after)


@pytest.mark.parametrize("name", HOLDERS)
def test_native_rollback_refusal_still_retires_holder(tmp_path, name):
    _exercise(tmp_path, name, deny=True)


@pytest.mark.parametrize("name", HOLDERS)
def test_native_holder_semantics_and_option_restoration(tmp_path, name):
    _exercise(tmp_path, name)
