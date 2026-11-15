"""Exact tampering fixture closes SQLite connections on supplied update refusal."""

import ast
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("deny_update", [False, True], ids=["normal", "update-refusal"])
def test_tamper_fixture_closes_connection(deny_update, tmp_path):
    source = (
        Path(__file__).resolve().parents[3]
        / "core/audit/tests/test_call_edge_store_consumers.py"
    )
    text = source.read_text()
    node = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef) and n.name == "_tamper_one_edge"
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
        == "3778839f742bb9701fc19b850f37b7c25356e9034604ba573f1f343ba3a3f922"
    )
    graph = tmp_path / "graph.sqlite"
    with closing(sqlite3.connect(graph)) as seed:
        seed.execute("CREATE TABLE nodes(name TEXT)")
        seed.executemany("INSERT INTO nodes VALUES (?)", [("f",), ("main",)])
        seed.commit()
    connections, denials = [], []

    def authorize(action, table, *rest):
        if action == sqlite3.SQLITE_UPDATE and table == "nodes":
            denials.append(action)
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def connect(path):
        assert path == graph
        con = sqlite3.connect(path)
        connections.append(con)
        if deny_update:
            con.set_authorizer(authorize)
        return con

    namespace = {"Path": Path, "sqlite3": SimpleNamespace(connect=connect)}
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    failed = False
    try:
        try:
            namespace["_tamper_one_edge"](graph)
        except sqlite3.DatabaseError as exc:
            assert exc.sqlite_errorcode == sqlite3.SQLITE_AUTH
            failed = True
        assert failed is deny_update and bool(denials) is deny_update
        assert len(connections) == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connections[0].execute("SELECT 1")
        with closing(sqlite3.connect(graph)) as verify:
            rows = verify.execute("SELECT name FROM nodes ORDER BY name").fetchall()
        assert rows == ([("f",), ("main",)] if deny_update else [("evil",), ("main",)])
    finally:
        for con in connections:
            con.close()
