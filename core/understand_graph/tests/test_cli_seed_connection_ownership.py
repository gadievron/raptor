"""CLI summary seed connections retire on native write failures."""

import os
import builtins
import sqlite3
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

from core.testing.state_isolation import pin_user_state_dirs
from core.understand_graph.store import open_graph
from core.understand_graph.tests import test_graph_query_cli as native

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


def _exercise(tmp_path, error=None, after=True, deny=False):
    records, closed, paths, imports = [], [], [], []
    failure = error("owned CLI seed query fault") if error else None

    class Connection:
        def __init__(self, connection):
            self.connection = connection

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
        connection = open_graph(path)
        records.append(connection)
        paths.append(Path(path))
        if deny:
            connection.set_authorizer(
                lambda action, *rest: sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_INSERT else sqlite3.SQLITE_OK,
            )
        return Connection(connection)

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.understand_graph.store" and fromlist == ("open_graph",) and level == 0:
            imports.append(name)
            return SimpleNamespace(open_graph=opened)
        return builtins.__import__(name, globals, locals, fromlist, level)

    function = native._seed_hostile_kind_graph
    namespace = {**function.__globals__, "__builtins__": {**vars(builtins), "__import__": imported}}
    body = FunctionType(function.__code__, namespace, function.__name__, function.__defaults__, function.__closure__)
    expected = error or (sqlite3.DatabaseError if deny else None)
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if deny else "owned CLI seed query fault") as caught:
                body(tmp_path)
            if failure is not None:
                assert caught.value is failure
        else:
            path = body(tmp_path)
            from contextlib import closing
            with closing(open_graph(path)) as observed, observed:
                assert observed.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] == 2
                assert observed.execute("SELECT COUNT(*) FROM edges").fetchone()[0] == 1
                assert observed.execute("SELECT kind FROM nodes WHERE id='n1'").fetchone()[0] == native._HOSTILE_KIND
        assert imports == ["core.understand_graph.store"]
        assert len(records) == 1
        assert closed == records
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            records[0].execute("SELECT 1")
        assert all(_owned_fds(path) == 0 for path in paths)
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)
        assert all(_owned_fds(path) == 0 for path in paths)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_cli_seed_query_faults_retire_connection(tmp_path, error, after):
    _exercise(tmp_path, error=error, after=after)


def test_native_cli_seed_insert_refusal_retires_connection(tmp_path):
    _exercise(tmp_path, deny=True)


def test_native_cli_seed_preserves_committed_terminal_bytes(tmp_path):
    _exercise(tmp_path)
