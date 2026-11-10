"""WAL fixture setup and read connections retire independently of workers."""

import builtins
import sqlite3
import threading
from types import FunctionType, SimpleNamespace

import pytest

from core.understand_graph import store
from core.understand_graph.tests import test_understand_graph as native


def _exercise(tmp_path, stage, error, after):
    records = []
    closed = []
    main = threading.current_thread()
    failure = error("owned WAL fixture SQL error") if error else None

    class Connection:
        def __init__(self, connection, label):
            self.connection = connection
            self.label = label
            self.calls = 0

        def execute(self, *args):
            self.calls += 1
            selected = error and self.label == stage and self.calls == 1
            if selected and not after:
                raise failure
            result = self.connection.execute(*args)
            if selected:
                raise failure
            return result

        def commit(self):
            return self.connection.commit()

        def close(self):
            self.connection.close()
            closed.append(self.label)

    def opened(path):
        connection = store.open_graph(path)
        if threading.current_thread() is not main:
            return connection
        label = "setup" if not records else "read"
        records.append((connection, label))
        return Connection(connection, label)

    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.understand_graph.store" and "open_graph" in fromlist:
            return SimpleNamespace(open_graph=opened)
        return builtins.__import__(name, globals, locals, fromlist, level)

    method = native.test_concurrent_writers_wal_mode
    body = FunctionType(method.__code__, {
        **method.__globals__,
        "__builtins__": {**vars(builtins), "__import__": importing},
    })
    try:
        if error:
            with pytest.raises(error) as caught:
                body(tmp_path)
            assert caught.value is failure
        else:
            body(tmp_path)
        assert [label for _, label in records] == (
            ["setup"] if error and stage == "setup" else ["setup", "read"]
        )
        assert closed == [label for _, label in records]
        for connection, _ in records:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                connection.execute("SELECT 1")
    finally:
        for connection, _ in records:
            connection.close()


@pytest.mark.parametrize("stage", ["setup", "read"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_wal_fixture_sql_errors_close_main_thread_connections(tmp_path, stage, error, after):
    _exercise(tmp_path, stage, error, after)


def test_native_concurrent_writers_preserve_data_and_retire_fixture_connections(tmp_path):
    _exercise(tmp_path, "read", None, True)
