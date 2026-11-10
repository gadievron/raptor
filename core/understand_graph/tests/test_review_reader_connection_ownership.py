"""Final-review fixture readers own native connections beyond transactions."""

import os
import sqlite3
from pathlib import Path
from types import FunctionType

import pytest

from core.testing.state_isolation import pin_user_state_dirs
from core.understand_graph.tests import test_final_commit_review as native
from core.project.project import ProjectManager

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
    count = 0
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            continue
        count += target == str(Path(path).resolve())
    return count


def _exercise(tmp_path, consumer, error=None, after=True, deny=False):
    records, closed, paths = [], [], []
    failure = error("owned commit review reader fault") if error else None
    original_list = ProjectManager.list_projects
    original_find = ProjectManager.find_project_for_target

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
        records.append(connection)
        paths.append(Path(path))
        if deny:
            connection.set_authorizer(
                lambda action, *rest: sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_SELECT else sqlite3.SQLITE_OK,
            )
        return Connection(connection)

    try:
        with pytest.MonkeyPatch.context() as patch:
            project = native.project.__wrapped__(tmp_path, patch)
            function = native._affects if consumer == "count" else native.test_localhost_uri_does_not_bypass_symlink_containment
            argument = project[2] if consumer == "count" else project
            body = FunctionType(function.__code__, {**function.__globals__, "open_graph": opened}, function.__name__, function.__defaults__, function.__closure__)
            expected = error or (sqlite3.DatabaseError if deny else None)
            if expected:
                with pytest.raises(expected, match="not authorized" if deny else "owned commit review reader fault") as caught:
                    body(argument)
                if failure is not None:
                    assert caught.value is failure
            else:
                result = body(argument)
                if consumer == "count":
                    assert result == 0
            assert len(records) == 1
            assert closed == records
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                records[0].execute("SELECT 1")
            assert _owned_fds(paths[0]) == 0
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)
        assert all(_owned_fds(path) == 0 for path in paths)
        assert ProjectManager.list_projects is original_list
        assert ProjectManager.find_project_for_target is original_find


@pytest.mark.parametrize("consumer", ["count", "direct"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_review_query_faults_retire_connections(tmp_path, consumer, error, after):
    _exercise(tmp_path, consumer, error, after)


@pytest.mark.parametrize("consumer", ["count", "direct"])
def test_native_review_query_refusal_retires_connections(tmp_path, consumer):
    _exercise(tmp_path, consumer, deny=True)


@pytest.mark.parametrize("consumer", ["count", "direct"])
def test_native_review_assertions_and_reader_retirement(tmp_path, consumer):
    _exercise(tmp_path, consumer)
