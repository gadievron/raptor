"""Validation-join fixture readers own native connections beyond transactions."""

import os
import sqlite3
from pathlib import Path
from types import FunctionType

import pytest

from core.understand_graph.tests import test_validates_join as native

pytestmark = pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(), reason="native descriptor observation requires procfs",
)


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
    failure = error("owned validation join reader fault") if error else None
    fault_index = 0 if consumer == "targets" else 1

    class Connection:
        def __init__(self, connection, index):
            self.connection = connection
            self.index = index

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def execute(self, *args):
            selected = error and self.index == fault_index
            if selected and not after:
                raise failure
            result = self.connection.execute(*args)
            if selected:
                result.close()
                raise failure
            return result

        def close(self):
            self.connection.close()
            closed.append(self.connection)

    def opened(path):
        connection = native.open_graph(path)
        index = len(records)
        paths.append(Path(path))
        records.append(connection)
        if deny and index == fault_index:
            connection.set_authorizer(
                lambda action, *rest: sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_SELECT else sqlite3.SQLITE_OK,
            )
        return Connection(connection, index)

    helper = native._validates_targets
    targets = FunctionType(helper.__code__, {**helper.__globals__, "open_graph": opened}, helper.__name__, helper.__defaults__, helper.__closure__)
    if consumer == "targets":
        target, run = tmp_path / "target", tmp_path / "run"
        graph = native._write_two_flow_run(run, target)
        native.save_json(run / "validation-outcomes.json", [{"finding_id": "FLOW-1", "status": "exploitable"}])
        native.ingest_validation_outcomes(run, str(target))
        argument = graph
        body = targets
    else:
        function = native.test_props_id_equality_joins_scan_findings
        body = FunctionType(function.__code__, {**function.__globals__, "open_graph": opened, "_validates_targets": targets}, function.__name__, function.__defaults__, function.__closure__)
        argument = tmp_path
    expected = error or (sqlite3.DatabaseError if deny else None)
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if deny else "owned validation join reader fault") as caught:
                body(argument)
            if failure is not None:
                assert caught.value is failure
        else:
            result = body(argument)
            if consumer == "targets":
                assert result == ["unchecked_flow://FLOW-1"]
        assert len(records) == fault_index + 1
        assert closed == records
        for connection in records:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                connection.execute("SELECT 1")
        assert all(_owned_fds(path) == 0 for path in paths)
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)
        assert all(_owned_fds(path) == 0 for path in paths)


@pytest.mark.parametrize("consumer", ["targets", "props"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_join_query_faults_retire_reader_connections(tmp_path, consumer, error, after):
    _exercise(tmp_path, consumer, error, after)


@pytest.mark.parametrize("consumer", ["targets", "props"])
def test_native_join_query_refusal_retires_connection(tmp_path, consumer):
    _exercise(tmp_path, consumer, deny=True)


@pytest.mark.parametrize("consumer", ["targets", "props"])
def test_native_validation_join_assertions_and_retirement(tmp_path, consumer):
    _exercise(tmp_path, consumer)
