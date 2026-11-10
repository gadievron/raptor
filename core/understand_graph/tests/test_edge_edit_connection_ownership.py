"""Edge-trust fixture editors retain SQLite ownership on SQL failures."""

import errno
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_edge_trust as native

EDITORS = [
    "test_doctored_edge_count_is_no_lane",
    "test_tampered_node_name_demotes_row_and_completeness",
    "test_deleted_row_reads_incomplete",
    "test_duplicate_row_cannot_mask_a_deletion",
    "test_forged_newer_sibling_only_drops_the_lane",
]


def _owned_fds(path):
    try:
        target = Path(path).stat()
    except FileNotFoundError:
        return 0
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
        count += (status.st_dev, status.st_ino) == (target.st_dev, target.st_ino)
    return count


def _exercise(tmp_path, name, error=None, after=True, deny=False):
    records = []
    closed = []
    failure = error("owned edge editor fault") if error else None
    path = tmp_path / "g.sqlite"

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
                lambda action, *rest: sqlite3.SQLITE_DENY if action in (
                    sqlite3.SQLITE_SELECT, sqlite3.SQLITE_UPDATE,
                    sqlite3.SQLITE_DELETE, sqlite3.SQLITE_INSERT,
                ) else sqlite3.SQLITE_OK,
            )
        return connection

    function = getattr(native.TestVerifiedMechanicalCallEdges, name)
    body = FunctionType(function.__code__, {
        **function.__globals__, "sqlite3": SimpleNamespace(**{**vars(sqlite3), "connect": connected}),
    }, function.__name__, function.__defaults__, function.__closure__)
    expected = error or (sqlite3.DatabaseError if deny else None)
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if deny else "owned edge editor fault") as caught:
                body(native.TestVerifiedMechanicalCallEdges(), tmp_path)
            if failure is not None:
                assert caught.value is failure
        else:
            body(native.TestVerifiedMechanicalCallEdges(), tmp_path)
        assert len(records) == 1
        assert closed == records
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            sqlite3.Connection.execute(records[0], "SELECT 1")
        assert _owned_fds(path) == 0
        with closing(sqlite3.connect(path, timeout=0.05)) as writer:
            writer.execute("BEGIN IMMEDIATE")
            writer.rollback()
    finally:
        for connection in records:
            sqlite3.Connection.close(connection)
        assert _owned_fds(path) == 0


@pytest.mark.parametrize("name", EDITORS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_editor_sql_faults_retire_connections(tmp_path, name, error, after):
    _exercise(tmp_path, name, error, after)


@pytest.mark.parametrize("name", EDITORS)
def test_native_editor_refusal_retires_connection(tmp_path, name):
    _exercise(tmp_path, name, deny=True)


@pytest.mark.parametrize("name", EDITORS)
def test_native_edge_edit_assertions_and_connection_retirement(tmp_path, name):
    _exercise(tmp_path, name)
