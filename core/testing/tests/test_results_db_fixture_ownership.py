"""Exact results fixture closes real SQLite connections on supplied refusal."""

import ast
import hashlib
from pathlib import Path
import sqlite3
from contextlib import closing

import pytest
from types import SimpleNamespace


@pytest.mark.parametrize("deny_schema", [False, True], ids=["normal", "schema-refusal"])
def test_results_fixture_closes_connection(deny_schema, tmp_path):
    root = Path(__file__).resolve().parents[3]
    source = root / "core/dataflow/tests/test_cvefix_bridge.py"
    text = source.read_text()
    node = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef) and n.name == "_results_db"
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
        == "815348337e21c396d4898f53a4ddf005d46516db1b4ffb167f49396aaf8006b4"
    )
    production = root / "core/dataflow/cvefix_walk.py"
    pt = production.read_text()
    assert (
        hashlib.sha256(pt.encode()).hexdigest()
        == "5956061b2faf6f8e02794d22ad6a36710b86f93ae2a63dbcca04b3ef987ffb61"
    )
    schema_node = next(
        n
        for n in ast.parse(pt).body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_SCHEMA" for t in n.targets)
    )
    schema = ast.literal_eval(schema_node.value)
    connections, denials = [], []

    def authorize(action, *args):
        if action == sqlite3.SQLITE_CREATE_TABLE:
            denials.append(action)
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def connect(path):
        con = sqlite3.connect(path)
        connections.append(con)
        if deny_schema:
            con.set_authorizer(authorize)
        return con

    namespace = {
        "Path": Path,
        "sqlite3": SimpleNamespace(connect=connect),
        "cvefix_walk": SimpleNamespace(_SCHEMA=schema),
    }
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    failed = False
    try:
        try:
            namespace["_results_db"](tmp_path / "results.sqlite")
        except sqlite3.DatabaseError as exc:
            assert exc.sqlite_errorcode == sqlite3.SQLITE_AUTH
            failed = True
        assert failed is deny_schema
        assert bool(denials) is deny_schema
        assert len(connections) == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connections[0].execute("SELECT 1")
        if not deny_schema:
            with closing(sqlite3.connect(tmp_path / "results.sqlite")) as verify:
                rows = verify.execute(
                    "SELECT fix_hash, cwe, after_count FROM walk_results ORDER BY fix_hash"
                ).fetchall()
            assert rows == [
                ("f1", "CWE-89", 1),
                ("f2", "CWE-79", 2),
                ("f3", "CWE-78", 1),
                ("f4", "CWE-22", 0),
            ]
    finally:
        for con in connections:
            con.close()
