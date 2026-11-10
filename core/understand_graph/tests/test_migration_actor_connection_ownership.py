"""Migration actor errors retire connections without changing crash semantics."""

import sqlite3
from contextlib import closing
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_migration as native

ACTORS = [
    ("test_crash_mid_swap_recovery_restores_legacy_rows", "ddl"),
    ("test_concurrent_first_open_mid_swap_preserves_rows", "ddl"),
    ("test_completed_swap_recovery_drops_leftover_tmp", "commit"),
]


def _exercise(tmp_path, name, phase, error=None, after=True, deny=False):
    records = []
    first_close_states = []
    failure = error("owned migration actor fault") if error else None

    class Connection(sqlite3.Connection):
        def execute(self, *args, **kwargs):
            self.calls += 1
            selected = error and self.calls == 1
            if selected and not after:
                raise failure
            result = super().execute(*args, **kwargs)
            if selected:
                result.close()
                raise failure
            return result

        def close(self):
            try:
                state = self.in_transaction
            except sqlite3.ProgrammingError:
                state = "closed"
            super().close()
            first_close_states.append(state)

    def connected(path):
        connection = sqlite3.connect(path, factory=Connection)
        connection.calls = 0
        records.append(connection)
        if deny:
            def authorize(action, arg, *rest):
                refused = action == sqlite3.SQLITE_ALTER_TABLE if phase == "ddl" else (
                    action == sqlite3.SQLITE_TRANSACTION and arg == "COMMIT"
                )
                return sqlite3.SQLITE_DENY if refused else sqlite3.SQLITE_OK
            connection.set_authorizer(authorize)
        return connection

    method = getattr(native, name)
    body = FunctionType(method.__code__, {
        **method.__globals__,
        "sqlite3": SimpleNamespace(connect=connected, OperationalError=sqlite3.OperationalError),
    })
    expected = error or (sqlite3.DatabaseError if deny else None)
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if deny else "owned migration actor fault") as caught:
                body(tmp_path)
            if failure is not None:
                assert caught.value is failure
        else:
            body(tmp_path)
        assert len(records) == 1
        assert first_close_states
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            sqlite3.Connection.execute(records[0], "SELECT 1")
        if not expected:
            if name == "test_crash_mid_swap_recovery_restores_legacy_rows":
                assert first_close_states[0] is True
            if phase == "commit":
                assert first_close_states[0] is False
            assert all(state == "closed" for state in first_close_states[1:])
        with closing(sqlite3.connect(tmp_path / "raptor.graph.sqlite", timeout=0.05)) as writer:
            writer.execute("BEGIN IMMEDIATE")
            writer.rollback()
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize("name,phase", ACTORS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_actor_sql_faults_retire_connection(tmp_path, name, phase, error, after):
    _exercise(tmp_path, name, phase, error, after)


@pytest.mark.parametrize("name,phase", ACTORS)
def test_native_actor_refusals_release_owned_connection(tmp_path, name, phase):
    _exercise(tmp_path, name, phase, deny=True)


@pytest.mark.parametrize("name,phase", ACTORS)
def test_native_crash_commit_points_and_recovery_assertions(tmp_path, name, phase):
    _exercise(tmp_path, name, phase)
