"""Rebuild fixture readers own connections outside native transaction scopes."""

import os
import sqlite3
from contextlib import closing
from pathlib import Path
from types import FunctionType

import pytest

from core.understand_graph.tests import test_ingest_run_rebuild as native


def _owned_fds(path):
    count = 0
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            continue
        count += target == str(Path(path).resolve())
    return count


def _exercise(tmp_path, consumer, error=None, after=True, deny=False):
    records = []
    closed = []
    paths = []
    failure = error("owned rebuild reader fault") if error else None

    class Connection:
        def __init__(self, connection):
            self.connection = connection

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def execute(self, *args):
            if error and not after:
                raise failure
            result = self.connection.execute(*args)
            if error:
                result.close()
                raise failure
            return result

        def close(self):
            self.connection.close()
            closed.append(self.connection)

    def opened(path):
        connection = native.open_graph(path)
        paths.append(Path(path))
        records.append(connection)
        if deny:
            connection.set_authorizer(
                lambda action, *rest: sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_SELECT else sqlite3.SQLITE_OK,
            )
        return Connection(connection)

    function = native._node_count if consumer == "count" else native.test_ingest_run_atomic_on_mid_ingest_crash
    body = FunctionType(function.__code__, {**function.__globals__, "open_graph": opened}, function.__name__, function.__defaults__, function.__closure__)
    expected = error or (sqlite3.DatabaseError if deny else None)
    try:
        with pytest.MonkeyPatch.context() as patch:
            if consumer == "count":
                target = tmp_path / "target"
                target.mkdir()
                run = tmp_path / "run"
                native._write_run_artifacts(run, target)
                graph = native.ingest_run(run, str(target))
                assert graph is not None
                invoke = lambda: body(graph)
            else:
                invoke = lambda: body(tmp_path, patch)
            if expected:
                with pytest.raises(expected, match="not authorized" if deny else "owned rebuild reader fault") as caught:
                    invoke()
                if failure is not None:
                    assert caught.value is failure
            else:
                result = invoke()
                if consumer == "count":
                    assert result > 0
            assert len(records) == 1
            assert closed == records
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                records[0].execute("SELECT 1")
            assert _owned_fds(paths[0]) == 0
            with closing(sqlite3.connect(paths[0], timeout=0.05)) as writer:
                writer.execute("BEGIN IMMEDIATE")
                writer.rollback()
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)
        assert all(_owned_fds(path) == 0 for path in paths)


@pytest.mark.parametrize("consumer", ["count", "crash"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_reader_sql_faults_retire_after_transaction_exit(tmp_path, consumer, error, after):
    _exercise(tmp_path, consumer, error, after)


@pytest.mark.parametrize("consumer", ["count", "crash"])
def test_native_reader_authorization_failure_retires_connection(tmp_path, consumer):
    _exercise(tmp_path, consumer, deny=True)


@pytest.mark.parametrize("consumer", ["count", "crash"])
def test_native_rebuild_assertions_and_reader_retirement(tmp_path, consumer):
    _exercise(tmp_path, consumer)
