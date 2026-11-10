"""Symlink-refusal fixtures retire SQLite before deleting their temporary tree."""

import os
import sqlite3
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_store_symlink_refusal as native

pytestmark = pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(), reason="native descriptor observation requires procfs",
)


def _owned_fds(path):
    resolved = str(Path(path).resolve())
    count = 0
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            continue
        count += target in (resolved, resolved + " (deleted)")
    return count


def _exercise(error=None, after=True, deny=False):
    records, closed, paths, retirement = [], [], [], []
    failure = error("owned symlink fixture fault") if error else None

    class Connection(sqlite3.Connection):
        def execute(self, *args, **kwargs):
            if error and not after:
                raise failure
            result = super().execute(*args, **kwargs)
            if error:
                result.close()
                raise failure
            return result

        def close(self):
            super().close()
            closed.append(self)

    def connected(path):
        connection = sqlite3.connect(path, factory=Connection)
        records.append(connection)
        paths.append(Path(path))
        if deny:
            connection.set_authorizer(
                lambda action, *rest: sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_CREATE_TABLE else sqlite3.SQLITE_OK,
            )
        return connection

    class Directory(native.TemporaryDirectory):
        def __exit__(self, *args):
            retirement.append({"closed": closed == records, "fds": sum(_owned_fds(path) for path in paths)})
            return super().__exit__(*args)

    function = native.TestSymlinkedDbRefused.test_symlinked_db_refused_and_target_untouched
    body = FunctionType(function.__code__, {**function.__globals__, "TemporaryDirectory": Directory,
        "sqlite3": SimpleNamespace(**{**vars(sqlite3), "connect": connected})}, function.__name__, function.__defaults__, function.__closure__)
    expected = error or (sqlite3.DatabaseError if deny else None)
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if deny else "owned symlink fixture fault") as caught:
                body(native.TestSymlinkedDbRefused())
            if failure is not None:
                assert caught.value is failure
        else:
            body(native.TestSymlinkedDbRefused())
        assert len(records) == len(retirement) == 1
        assert all(not path.exists() for path in paths)
        assert closed == records
        assert retirement == [{"closed": True, "fds": 0}]
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            sqlite3.Connection.execute(records[0], "SELECT 1")
        assert all(_owned_fds(path) == 0 for path in paths)
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)
        assert all(_owned_fds(path) == 0 for path in paths)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_fixture_sql_error_retires_connection_before_directory(error, after):
    _exercise(error, after)


def test_native_create_refusal_retires_connection_before_directory():
    _exercise(deny=True)


def test_native_symlink_refusal_and_fixture_retirement():
    _exercise()
