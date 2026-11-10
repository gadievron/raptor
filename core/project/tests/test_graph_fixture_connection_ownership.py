"""Graph seeding fixtures retire their actual SQLite connections."""

import sqlite3
from contextlib import closing
from types import FunctionType

import pytest

from core.project.tests import test_cli_graph as native


def _consumer(opened):
    body = FunctionType(
        native._create_graph.__code__,
        {**native._create_graph.__globals__, "open_graph": opened},
    )
    body.__kwdefaults__ = dict(native._create_graph.__kwdefaults__)
    return body


def _closed(connection):
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


@pytest.mark.parametrize("part", ["nodes", "edges"])
def test_native_seed_error_closes_connection(tmp_path, part):
    connections = []

    def opened(path):
        connection = native.open_graph(path)
        connections.append(connection)
        return connection

    values = {"nodes": [{"name": object()}]} if part == "nodes" else {"edges": [{"kind": object()}]}
    try:
        with pytest.raises(sqlite3.ProgrammingError):
            _consumer(opened)(tmp_path, **values)
        assert len(connections) == 1
        _closed(connections[0])
    finally:
        for connection in connections:
            connection.close()


@pytest.mark.parametrize("stage", ["snapshot", "commit"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_seed_operation_error_closes_connection(tmp_path, stage, error):
    connections = []
    failure = error("owned graph seed failure")
    closed = []

    class ObservedConnection:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, *args):
            result = self.connection.execute(*args)
            if stage == "snapshot":
                raise failure
            return result

        def commit(self):
            self.connection.commit()
            if stage == "commit":
                raise failure

        def close(self):
            self.connection.close()
            closed.append(self.connection)

    def opened(path):
        connection = native.open_graph(path)
        connections.append(connection)
        return ObservedConnection(connection)

    try:
        with pytest.raises(error) as caught:
            _consumer(opened)(tmp_path)
        assert caught.value is failure
        assert len(connections) == 1
        assert closed == connections
        _closed(connections[0])
    finally:
        for connection in connections:
            connection.close()


def test_success_commits_graph_and_closes_connection(tmp_path):
    connections = []

    def opened(path):
        connection = native.open_graph(path)
        connections.append(connection)
        return connection

    try:
        path = _consumer(opened)(tmp_path, nodes=[{"name": "kept"}])
        assert path == tmp_path / "graph" / native.GRAPH_FILENAME
        assert len(connections) == 1
        _closed(connections[0])
        with closing(sqlite3.connect(path)) as reader:
            assert reader.execute("SELECT name FROM nodes").fetchall() == [("kept",)]
            assert reader.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 1
    finally:
        for connection in connections:
            connection.close()
