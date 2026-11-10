"""Graph backfill fixtures close connections without losing transaction semantics."""

import json
import sqlite3
from contextlib import closing
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph.tests import test_understand_graph as native


def _exercise(tmp_path, stage, error, after):
    records = []
    events = []
    failure = error("owned backfill SQL error") if error else None

    class Connection:
        def __init__(self, connection):
            self.connection = connection

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            events.append(("exit", args[0]))
            return self.connection.__exit__(*args)

        def execute(self, sql, *args):
            selected = stage == ("select" if sql.startswith("SELECT") else "update")
            if error and selected and not after:
                raise failure
            result = self.connection.execute(sql, *args)
            if error and selected:
                raise failure
            return result

        def close(self):
            self.connection.close()
            events.append(("close", None))

    def connect(path):
        connection = sqlite3.connect(path)
        records.append((connection, path, connection.execute(
            "SELECT props_json FROM nodes WHERE kind='entry_point' LIMIT 1",
        ).fetchone()[0]))
        return Connection(connection)

    method = native.test_context_map_backfills_name_from_graph_row
    body = FunctionType(method.__code__, {
        **method.__globals__, "sqlite3": SimpleNamespace(connect=connect),
    })
    try:
        if error:
            with pytest.raises(error) as caught:
                body(tmp_path)
            assert caught.value is failure
        else:
            body(tmp_path)
        assert len(records) == 1
        connection, path, before = records[0]
        assert events == [("exit", error), ("close", None)]
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
        with closing(sqlite3.connect(path)) as reader:
            stored = reader.execute(
                "SELECT props_json FROM nodes WHERE kind='entry_point' LIMIT 1",
            ).fetchone()[0]
        if error:
            assert stored == before
        else:
            expected = json.loads(before)
            for key in ("name", "entry", "path"):
                expected.pop(key, None)
            assert json.loads(stored) == expected
    finally:
        for connection, _, _ in records:
            connection.close()


@pytest.mark.parametrize("stage", ["select", "update"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_sql_errors_rollback_before_connection_retirement(tmp_path, stage, error, after):
    _exercise(tmp_path, stage, error, after)


def test_native_success_commits_before_connection_retirement(tmp_path):
    _exercise(tmp_path, "update", None, True)
