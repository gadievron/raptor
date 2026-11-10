"""Producer-scoped diff fixture connections close after transactions and faults."""

import os
import sqlite3
from pathlib import Path
from types import FunctionType

import pytest

from core.testing.state_isolation import pin_user_state_dirs
from core.understand_graph.tests import test_diff_scoping as native

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


SITES = [
    ("_bump_created_at", 0),
    ("test_default_diff_compares_understand_pair_across_interleaved_scan", 0),
    ("test_single_explicit_endpoint_defaults_within_its_producer", 0),
    ("test_explicit_snapshot_pair_stays_unrestricted", 0),
    ("test_unchecked_reads_the_nested_evidence_key", 0),
    ("test_explicit_older_head_defaults_base_backwards_in_time", 0),
    ("test_explicit_older_head_defaults_base_backwards_in_time", 1),
]


def _exercise(tmp_path, site, error=None, after=True, deny=False):
    name, ordinal = site
    records, closed, paths = [], [], []
    failure = error("owned diff connection fault") if error else None

    class Connection:
        def __init__(self, connection, selected):
            self.connection = connection
            self.selected = selected

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def execute(self, *args):
            if error and self.selected and not after:
                raise failure
            result = self.connection.execute(*args)
            if error and self.selected:
                result.close()
                raise failure
            return result

        def close(self):
            self.connection.close()
            closed.append(self.connection)

    def opened(path):
        connection = native.open_graph(path)
        selected = len(records) == ordinal
        records.append(connection)
        paths.append(Path(path))
        if deny and selected:
            connection.set_authorizer(
                lambda action, *rest: sqlite3.SQLITE_DENY
                if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_UPDATE)
                else sqlite3.SQLITE_OK,
            )
        return Connection(connection, selected)

    def bump(*args):
        # Incidental helper calls preserve the real transaction and own its handle.
        from contextlib import closing
        graph_path, producer, stamp = args
        with closing(native.open_graph(graph_path)) as connection, connection:
            connection.execute("UPDATE snapshots SET created_at=? WHERE producer=?", (stamp, producer))

    function = getattr(native, name)
    body = FunctionType(function.__code__, {**function.__globals__, "open_graph": opened, "_bump_created_at": bump}, function.__name__, function.__defaults__, function.__closure__)
    if name == "_bump_created_at":
        graph_path = native._write_understand_run(tmp_path / "run", tmp_path / "target")
        args = (graph_path, "understand", "2026-01-01T00:00:00+00:00")
    else:
        args = (tmp_path,)
    expected = error or (sqlite3.DatabaseError if deny else None)
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if deny else "owned diff connection fault") as caught:
                body(*args)
            if failure is not None:
                assert caught.value is failure
        else:
            body(*args)
        assert len(records) > ordinal
        assert closed == records
        for connection in records:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                connection.execute("SELECT 1")
        assert all(_owned_fds(path) == 0 for path in paths)
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)
        assert all(_owned_fds(path) == 0 for path in paths)


@pytest.mark.parametrize("site", SITES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_diff_query_faults_retire_connections(tmp_path, site, error, after):
    _exercise(tmp_path, site, error=error, after=after)


@pytest.mark.parametrize("site", SITES)
def test_native_diff_sql_refusal_retires_connection(tmp_path, site):
    _exercise(tmp_path, site, deny=True)


@pytest.mark.parametrize("site", SITES)
def test_native_diff_assertions_and_retirement(tmp_path, site):
    _exercise(tmp_path, site)
