"""Exact graph fixture closes SQLite connections under supplied schema refusal."""

import ast
import hashlib
import json
from pathlib import Path
import sqlite3
from contextlib import closing

import pytest
from types import SimpleNamespace


@pytest.mark.parametrize("deny_schema", [False, True], ids=["normal", "schema-refusal"])
def test_graph_fixture_closes_connection(deny_schema, tmp_path):
    root = Path(__file__).resolve().parents[3]
    source = root / "core/audit/tests/test_binary_bridge.py"
    text = source.read_text()
    assert (
        hashlib.sha256(text.encode()).hexdigest()
        == "8ea9b26dc4eb937796998e51c8d91f951aad3c8aae4d7c059254ea2589e79e73"
    )
    node = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef) and n.name == "_create_graph_store"
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
        == "1a05b93a3ebd50868330efe593aab9ee9669151705bd20b3a9636b9929ac79bb"
    )
    connections, denials = [], []

    def authorize(action, *args):
        if action == sqlite3.SQLITE_CREATE_TABLE:
            denials.append(action)
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def connect(path):
        assert path == tmp_path / "graph/binary-graph.sqlite"
        con = sqlite3.connect(path)
        connections.append(con)
        if deny_schema:
            con.set_authorizer(authorize)
        return con

    namespace = {
        "Path": Path,
        "sqlite3": SimpleNamespace(connect=connect),
        "json": json,
    }
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    failed = False
    try:
        try:
            namespace["_create_graph_store"](
                tmp_path,
                [
                    {
                        "caller": "process_input",
                        "sink": "system",
                        "kind": "CALLS_SURFACE",
                    }
                ],
            )
        except sqlite3.DatabaseError as exc:
            assert exc.sqlite_errorcode == sqlite3.SQLITE_AUTH
            failed = True
        assert failed is deny_schema
        assert bool(denials) is deny_schema
        assert len(connections) == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connections[0].execute("SELECT 1")
        if not deny_schema:
            with closing(
                sqlite3.connect(tmp_path / "graph/binary-graph.sqlite")
            ) as verify:
                assert verify.execute("SELECT key,value FROM metadata").fetchall() == [
                    ("schema_version", "1")
                ]
                assert verify.execute("SELECT * FROM snapshots").fetchall() == [
                    ("snap1", "abc123", "/path/to/binary", "2026-01-01T00:00:00")
                ]
                assert verify.execute(
                    "SELECT id,kind,name FROM nodes ORDER BY id"
                ).fetchall() == [
                    ("node:fn:0", "function", "process_input"),
                    ("node:import:0", "import", "system"),
                ]
                assert verify.execute("SELECT * FROM edges").fetchall() == [
                    (
                        "snap1",
                        "edge:0",
                        "CALLS_SURFACE",
                        "node:fn:0",
                        "node:import:0",
                        "candidate",
                        "{}",
                    )
                ]
    finally:
        for con in connections:
            con.close()
