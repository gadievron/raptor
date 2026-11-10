"""Foreign-store fixtures retire their native schema-creation connections."""

import os
import sqlite3
from contextlib import closing
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_call_edge_ingest as ingest
from core.understand_graph.tests import test_store_fd_honest as honest


def _owned_fds(path):
    count = 0
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            continue
        count += target in (str(Path(path).resolve()), str(Path(path).resolve()) + " (deleted)")
    return count


def _exercise(tmp_path, consumer, error=None, after=True, deny=False):
    records = []
    closed = []
    paths = []
    failure = error("owned foreign fixture fault") if error else None

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
        paths.append(Path(path))
        records.append(connection)
        if deny:
            connection.set_authorizer(
                lambda action, *rest: sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_CREATE_TABLE else sqlite3.SQLITE_OK,
            )
        return connection

    class OwnedPath(type(tmp_path)):
        def read_bytes(self):
            assert closed == records
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                sqlite3.Connection.execute(records[0], "SELECT 1")
            assert _owned_fds(self) == 0
            return super().read_bytes()

    function = ingest.test_junk_store_costs_the_ingest_not_the_caller if consumer == "ingest" else honest._make_foreign
    body = FunctionType(function.__code__, {**function.__globals__, "sqlite3": SimpleNamespace(**{
        **vars(sqlite3), "connect": connected,
    })}, function.__name__, function.__defaults__, function.__closure__)
    expected = error or (sqlite3.DatabaseError if deny else None)
    argument = tmp_path if consumer == "ingest" else OwnedPath(tmp_path / "foreign.sqlite")
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if deny else "owned foreign fixture fault") as caught:
                body(argument)
            if failure is not None:
                assert caught.value is failure
        else:
            result = body(argument)
            if consumer == "honest":
                assert result == Path(argument).read_bytes()
                with closing(sqlite3.connect(argument)) as reader:
                    assert reader.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("marker",)]
        assert len(records) == 1
        assert closed == records
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            sqlite3.Connection.execute(records[0], "SELECT 1")
        assert all(_owned_fds(path) == 0 for path in paths)
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)
        assert all(_owned_fds(path) == 0 for path in paths)


@pytest.mark.parametrize("consumer", ["ingest", "honest"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_fixture_create_errors_retire_connections(tmp_path, consumer, error, after):
    _exercise(tmp_path, consumer, error, after)


@pytest.mark.parametrize("consumer", ["ingest", "honest"])
def test_native_create_refusal_retires_fixture_connection(tmp_path, consumer):
    _exercise(tmp_path, consumer, deny=True)


@pytest.mark.parametrize("consumer", ["ingest", "honest"])
def test_native_foreign_fixture_success_and_retirement(tmp_path, consumer):
    _exercise(tmp_path, consumer)
