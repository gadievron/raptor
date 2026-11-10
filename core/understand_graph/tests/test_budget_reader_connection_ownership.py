"""Ingest-budget fixture readers retire when native read queries abort."""

import sqlite3
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_ingest_budget as native

from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def _user_state_in_tmp(tmp_path):
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / "user")
        patch.setenv("HOME", str(tmp_path / "home"))
        patch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
        patch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
        patch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
        yield


READERS = ["test_ingest_records_artifact_digests", "test_oversized_artifact_degrades_to_skip"]


def _exercise(tmp_path, name, error=None, after=True, deny=False):
    records = []
    closed = []
    failure = error("owned budget reader fault") if error else None
    before_budget = native.ingest._ARTIFACT_MAX_BYTES

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
            super().close()
            closed.append(self)

    def connected(path):
        connection = sqlite3.connect(path, factory=Connection)
        connection.calls = 0
        records.append(connection)
        if deny:
            connection.set_authorizer(
                lambda action, *rest: sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_SELECT else sqlite3.SQLITE_OK,
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
                if name == "test_oversized_artifact_degrades_to_skip":
                    body(tmp_path, patch)
                else:
                    body(tmp_path)

            if expected:
                with pytest.raises(expected, match="not authorized" if deny else "owned budget reader fault") as caught:
                    invoke()
                if failure is not None:
                    assert caught.value is failure
            else:
                invoke()
            assert len(records) == 1
            assert closed == records
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                sqlite3.Connection.execute(records[0], "SELECT 1")
        assert native.ingest._ARTIFACT_MAX_BYTES == before_budget
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize("name", READERS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_reader_query_faults_retire_connection(tmp_path, name, error, after):
    _exercise(tmp_path, name, error, after)


@pytest.mark.parametrize("name", READERS)
def test_native_authorizer_error_retires_connection(tmp_path, name):
    _exercise(tmp_path, name, deny=True)


@pytest.mark.parametrize("name", READERS)
def test_native_ingest_budget_assertions_and_connection_cleanup(tmp_path, name):
    _exercise(tmp_path, name)
