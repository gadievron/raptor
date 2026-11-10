"""Owned SQLite cursor teardown must leave its borrowed queue usable."""
import json
import sqlite3
import sys
from types import SimpleNamespace

import pytest

from core.audit.cross_entry import progress as module


@pytest.fixture
def cursor_io(tmp_path, monkeypatch):
    state = {"cursors": [], "closes": 0, "cleanup": None, "primary": None}

    class OwnedCursor(sqlite3.Cursor):
        def close(self):
            state["primary"] = sys.exc_info()[1]
            super().close()
            state["closes"] += 1
            if state["cleanup"] is not None:
                raise state["cleanup"]

    class Connection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith("SELECT * FROM jobs WHERE namespace=? AND status IN ") and sql.endswith(" ORDER BY rowid"):
                cursor = self.cursor(factory=OwnedCursor)
                state["cursors"].append(cursor)
                return cursor.execute(sql, parameters)
            return super().execute(sql, parameters)

    def connect(*args, **kwargs):
        return sqlite3.connect(*args, **kwargs, factory=Connection)

    monkeypatch.setattr(module, "sqlite3", SimpleNamespace(**{**vars(sqlite3), "connect": connect}))
    queue = module.WorkQueue(tmp_path, "main")
    state["queue"] = queue
    try:
        queue.add_views(["owned.c"])
        view = queue.db.execute("SELECT id FROM views").fetchone()[0]
        state["view"] = view
        for number in range(2):
            queue.add_jobs(view, [(str(number), "")])
        jobs = queue.db.execute("SELECT id FROM jobs ORDER BY rowid").fetchall()
        for number, row in enumerate(jobs):
            queue.finish(view, row[0], "complete", {"key": f"evidence{number}"})
        state["last_job"] = jobs[-1][0]
        yield state
    finally:
        for cursor in state["cursors"]:
            sqlite3.Cursor.close(cursor)
        sqlite3.Connection.close(queue.db)


def _malformed(state):
    queue = state["queue"]
    queue.db.execute("UPDATE jobs SET result=? WHERE id=?", ("{", state["last_job"]))
    queue.db.commit()


def _assert_cursor_retired_database_borrowed(state):
    assert len(state["cursors"]) == state["closes"] == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        state["cursors"][0].fetchone()
    assert state["queue"].db.execute("SELECT 1").fetchone()[0] == 1


def test_native_json_refusal_survives_secondary_cursor_close(cursor_io):
    _malformed(cursor_io)
    cursor_io["cleanup"] = OSError("after native cursor close")
    with pytest.raises(json.JSONDecodeError) as raised:
        cursor_io["queue"]._undelivered_count()
    assert raised.value is cursor_io["primary"]
    _assert_cursor_retired_database_borrowed(cursor_io)


@pytest.mark.parametrize("operation", ["summary", "delivery"])
@pytest.mark.parametrize("close_type", [None, MemoryError, SystemExit])
def test_malformed_later_row_retains_identity(cursor_io, operation, close_type):
    _malformed(cursor_io)
    cursor_io["cleanup"] = close_type("after native cursor close") if close_type else None
    with pytest.raises(json.JSONDecodeError) as raised:
        if operation == "summary":
            cursor_io["queue"].summary()
        else:
            cursor_io["queue"].undelivered()
    assert raised.value is cursor_io["primary"]
    _assert_cursor_retired_database_borrowed(cursor_io)


@pytest.mark.parametrize("mode", ["exhaust", "explicit-close"])
@pytest.mark.parametrize("close_type", [None, OSError, KeyboardInterrupt])
def test_fresh_cursor_close_failures_remain_visible(cursor_io, mode, close_type):
    cleanup = close_type("after native cursor close") if close_type else None
    cursor_io["cleanup"] = cleanup
    iterator = cursor_io["queue"]._undelivered_rows()
    if mode == "explicit-close":
        assert next(iterator)[2] == "evidence0"
        assert cursor_io["closes"] == 0
        assert cursor_io["queue"].db.execute("SELECT 1").fetchone()[0] == 1

    def finish():
        if mode == "explicit-close":
            iterator.close()
        else:
            assert [entry[2] for entry in iterator] == ["evidence0", "evidence1"]

    if cleanup is None:
        finish()
    else:
        with pytest.raises(close_type) as raised:
            finish()
        assert raised.value is cleanup
    _assert_cursor_retired_database_borrowed(cursor_io)


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit])
def test_interrupted_iteration_retains_primary(cursor_io, primary_type):
    iterator = cursor_io["queue"]._undelivered_rows()
    assert next(iterator)[2] == "evidence0"
    primary = primary_type("owned iteration interrupted")
    cursor_io["cleanup"] = OSError("after native cursor close")
    with pytest.raises(primary_type) as raised:
        iterator.throw(primary)
    assert raised.value is primary
    _assert_cursor_retired_database_borrowed(cursor_io)
