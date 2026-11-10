"""Guard fixtures retire native schema and lock connections on setup faults."""

import os
import sqlite3
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

from core.testing.state_isolation import pin_user_state_dirs
from core.understand_graph.tests import test_guard_adoption as native

pytestmark = pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(), reason="native descriptor observation requires procfs",
)


@pytest.fixture(autouse=True)
def _user_state_in_tmp(tmp_path):
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / "user")
        patch.setenv("HOME", str(tmp_path / "home"))
        patch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
        patch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
        patch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
        yield


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


SITES = ["test_schema_newer_degrades_and_keeps_the_store", "test_lock_contention_never_quarantines"]


def _exercise(tmp_path, name, error=None, after=True, deny=False):
    records, closed, paths = [], [], []
    failure = error("owned guard fixture fault") if error else None

    class Connection:
        def __init__(self, connection):
            self.connection = connection

        @property
        def isolation_level(self):
            return self.connection.isolation_level

        @isolation_level.setter
        def isolation_level(self, value):
            self.connection.isolation_level = value

        def execute(self, *args):
            if error and not after:
                raise failure
            result = self.connection.execute(*args)
            if error:
                result.close()
                raise failure
            return result

        def commit(self):
            return self.connection.commit()

        def close(self):
            self.connection.close()
            closed.append(self.connection)

    def opened(path):
        connection = sqlite3.connect(path) if name == SITES[0] else native.open_graph(path)
        records.append(connection)
        paths.append(Path(path))
        if deny:
            connection.set_authorizer(
                lambda action, *rest: sqlite3.SQLITE_DENY
                if action == (sqlite3.SQLITE_PRAGMA if name == SITES[0] else sqlite3.SQLITE_TRANSACTION)
                else sqlite3.SQLITE_OK,
            )
        return Connection(connection)

    function = getattr(native, name)
    namespace = {**function.__globals__}
    namespace.update({"sqlite3": SimpleNamespace(connect=opened)} if name == SITES[0] else {"open_graph": opened})
    body = FunctionType(function.__code__, namespace, function.__name__, function.__defaults__, function.__closure__)
    expected = error or (sqlite3.DatabaseError if deny else None)
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if deny else "owned guard fixture fault") as caught:
                body(tmp_path)
            if failure is not None:
                assert caught.value is failure
        else:
            body(tmp_path)
        assert len(records) == 1
        assert closed == records
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            records[0].execute("SELECT 1")
        assert all(_owned_fds(path) == 0 for path in paths)
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)
        assert all(_owned_fds(path) == 0 for path in paths)


@pytest.mark.parametrize("name", SITES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_guard_fixture_setup_faults_retire_connection(tmp_path, name, error, after):
    _exercise(tmp_path, name, error=error, after=after)


@pytest.mark.parametrize("name", SITES)
def test_native_guard_fixture_refusal_retires_connection(tmp_path, name):
    _exercise(tmp_path, name, deny=True)


@pytest.mark.parametrize("name", SITES)
def test_native_guard_assertions_and_connection_retirement(tmp_path, name):
    _exercise(tmp_path, name)
