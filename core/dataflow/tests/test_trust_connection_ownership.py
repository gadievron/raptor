"""Own synthetic SQLite reader lifetime, preserving handled failed reports."""
from contextlib import closing
import sqlite3
from types import SimpleNamespace

import pytest

from core.dataflow import trust_corpus_report as module
from core.dataflow.tests.test_trust_corpus_report import _make_db, _row


@pytest.fixture
def connection_io(tmp_path, monkeypatch):
    path = tmp_path / "owned?#%.sqlite"
    _make_db(path, [_row("owned-fix", "CWE-79", "CVE-OWNED", "Python", "not_sound", "smt", "suppress_fp_failed(after=1)")])
    state = {"path": path, "connections": [], "closes": 0, "rows": 0,
             "row_error": None, "close_error": None, "aggregations": 0, "before": path.read_bytes()}
    native_classify = module._classify_not_sound_mode

    class Cursor(sqlite3.Cursor):
        def __iter__(self):
            return self

        def __next__(self):
            row = super().__next__()
            state["rows"] += 1
            if state["row_error"] is not None:
                raise state["row_error"]
            return row

    class Connection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.lstrip().startswith("SELECT cve_id, cwe"):
                return self.cursor(factory=Cursor).execute(sql, parameters)
            return super().execute(sql, parameters)

        def close(self):
            super().close()
            state["closes"] += 1
            if state["close_error"] is not None:
                raise state["close_error"]

    def connect(*args, **kwargs):
        assert args == (path.resolve().as_uri() + "?mode=ro",) and kwargs == {"uri": True}
        connection = sqlite3.connect(*args, **kwargs, factory=Connection)
        state["connections"].append(connection)
        try:
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                connection.execute("CREATE TABLE forbidden_write(value TEXT)")
        except BaseException:
            sqlite3.Connection.close(connection)
            raise
        return connection

    def classify(detail):
        state["aggregations"] += 1
        assert state["closes"] == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            sqlite3.Connection.execute(state["connections"][0], "SELECT 1")
        return native_classify(detail)

    monkeypatch.setattr(module, "sqlite3", SimpleNamespace(**{**vars(sqlite3), "connect": connect}))
    monkeypatch.setattr(module, "_classify_not_sound_mode", classify)
    try:
        yield state
    finally:
        for connection in state["connections"]:
            sqlite3.Connection.close(connection)


def _missing(state):
    with closing(sqlite3.connect(state["path"])) as db:
        db.execute("DROP TABLE synth_results")
        db.commit()
    state["before"] = state["path"].read_bytes()


def _assert_retired(state):
    assert state["closes"] == len(state["connections"]) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        state["connections"][0].execute("SELECT 1")
    assert state["path"].read_bytes() == state["before"]


def test_unhandled_iteration_interrupt_survives_secondary_close(connection_io):
    primary = KeyboardInterrupt("after native owned SQLite row")
    connection_io.update(row_error=primary, close_error=OSError("after native SQLite close"))
    with pytest.raises(KeyboardInterrupt) as raised:
        module.analyze(connection_io["path"])
    assert raised.value is primary
    assert connection_io["rows"] == 1 and connection_io["aggregations"] == 0
    _assert_retired(connection_io)


@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, MemoryError])
def test_unhandled_operation_error_keeps_identity(connection_io, primary_type, close_type):
    primary = primary_type("after native owned SQLite row")
    connection_io.update(row_error=primary, close_error=close_type("after native SQLite close"))
    with pytest.raises(primary_type) as raised:
        module.analyze(connection_io["path"])
    assert raised.value is primary
    assert connection_io["rows"] == 1 and connection_io["aggregations"] == 0
    _assert_retired(connection_io)


@pytest.mark.parametrize("query_failure", ["missing-table", "after-row"])
@pytest.mark.parametrize("close_type", [None, OSError, sqlite3.OperationalError, KeyboardInterrupt])
def test_handled_query_error_keeps_failed_report_and_fresh_close_policy(connection_io, query_failure, close_type):
    if query_failure == "missing-table":
        _missing(connection_io)
    else:
        connection_io["row_error"] = sqlite3.OperationalError("after native owned row")
    cleanup = close_type("after native SQLite close") if close_type else None
    connection_io["close_error"] = cleanup
    if cleanup is None:
        report = module.analyze(connection_io["path"])
        assert report.read_state == "failed" and report.read_rows is None
        assert report.read_reason == "synth_results query unavailable"
        assert report.processed == 0
    else:
        with pytest.raises(close_type) as raised:
            module.analyze(connection_io["path"])
        assert raised.value is cleanup
    assert connection_io["rows"] == int(query_failure == "after-row")
    assert connection_io["aggregations"] == 0
    _assert_retired(connection_io)


@pytest.mark.parametrize("close_type", [None, OSError, sqlite3.OperationalError, KeyboardInterrupt, SystemExit])
def test_healthy_snapshot_and_fresh_close_visibility(connection_io, close_type):
    cleanup = close_type("after native SQLite close") if close_type else None
    connection_io["close_error"] = cleanup
    if cleanup is None:
        report = module.analyze(connection_io["path"])
        assert report.read_state == "completed" and report.read_rows == 1
        assert report.processed == report.not_sound == 1 and report.sound == 0
        assert dict(report.not_sound_modes) == {"suppress_fp_failed": 1}
        assert connection_io["aggregations"] == 1
    else:
        with pytest.raises(close_type) as raised:
            module.analyze(connection_io["path"])
        assert raised.value is cleanup
        assert connection_io["aggregations"] == 0
    assert connection_io["rows"] == 1
    _assert_retired(connection_io)
