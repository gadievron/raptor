"""Aggregate fixture readers retire independently of native transaction exits."""

import errno
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from types import FunctionType

import pytest

from core.understand_graph.tests import test_aggregate_hygiene as native


def _owned_fds(path):
    try:
        status = Path(path).stat()
    except FileNotFoundError:
        return 0
    identity = status.st_dev, status.st_ino
    for directory in ("/proc/self/fd", "/dev/fd"):
        try:
            names = os.listdir(directory)
            break
        except FileNotFoundError:
            continue
    else:
        raise RuntimeError("native descriptor observation is unavailable")
    count = 0
    for name in names:
        if not name.isdecimal():
            continue
        try:
            status = os.fstat(int(name))
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
            continue
        count += (status.st_dev, status.st_ino) == identity
    return count


def _exercise(tmp_path, name, error=None, after=True, deny=False):
    records = []
    closed = []
    paths = []
    failure = error("owned aggregate reader fault") if error else None

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

    function = getattr(native, name)
    body = FunctionType(function.__code__, {**function.__globals__, "open_graph": opened}, function.__name__, function.__defaults__, function.__closure__)
    expected = error or (sqlite3.DatabaseError if deny else None)
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if deny else "owned aggregate reader fault") as caught:
                body(tmp_path)
            if failure is not None:
                assert caught.value is failure
        else:
            body(tmp_path)
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


READERS = ["test_created_at_minted_in_one_format", "test_binary_verdict_snapshot_key_is_content_hashed"]


@pytest.mark.parametrize("name", READERS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_aggregate_query_faults_retire_connections(tmp_path, name, error, after):
    _exercise(tmp_path, name, error, after)


@pytest.mark.parametrize("name", READERS)
def test_native_select_refusal_retires_aggregate_reader(tmp_path, name):
    _exercise(tmp_path, name, deny=True)


@pytest.mark.parametrize("name", READERS)
def test_native_aggregate_assertions_and_reader_retirement(tmp_path, name):
    _exercise(tmp_path, name)
