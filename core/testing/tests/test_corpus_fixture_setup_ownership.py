"""Exact corpus fixture closes SQLite connections across supplied schema refusal."""

import ast
import hashlib
from contextlib import closing
from pathlib import Path
import sqlite3
import time
from types import SimpleNamespace

import pytest

PINS = {
    "_make_db": "c3247a4ce357d9a661de3de560dba14acfcd0b0b1e92ee0d21a95d9b3fe67f86",
    "_row": "067befecfc8c410236f70a2b4587e39163b5a80c0f42701870ba54591a901e47",
}


@pytest.mark.parametrize("deny_schema", [False, True], ids=["normal", "schema-refusal"])
def test_corpus_fixture_closes_connection(deny_schema, tmp_path):
    source = (
        Path(__file__).resolve().parents[3]
        / "core/dataflow/tests/test_trust_corpus_report.py"
    )
    text = source.read_text()
    nodes = [
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef) and n.name in PINS
    ]
    assert len(nodes) == 2
    assert all(
        hashlib.sha256(ast.get_source_segment(text, n).encode()).hexdigest()
        == PINS[n.name]
        for n in nodes
    )
    connections, denials = [], []

    def authorize(action, table, *rest):
        if action == sqlite3.SQLITE_CREATE_TABLE and table == "synth_results":
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
        "time": time,
    }
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace
    )
    row = namespace["_row"](
        "owned-fix",
        "CWE-79",
        "CVE-OWNED",
        "Python",
        "not_sound",
        "smt",
        "suppress_fp_failed(after=1)",
    )
    failed = False
    before = time.time()
    try:
        try:
            namespace["_make_db"](tmp_path / "results.sqlite", [row])
        except sqlite3.DatabaseError as exc:
            assert exc.sqlite_errorcode == sqlite3.SQLITE_AUTH
            failed = True
        after = time.time()
        assert failed is deny_schema and bool(denials) is deny_schema
        assert len(connections) == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connections[0].execute("SELECT 1")
        if not deny_schema:
            with closing(sqlite3.connect(tmp_path / "results.sqlite")) as verify:
                saved = verify.execute("SELECT * FROM synth_results").fetchall()
            assert len(saved) == 1 and saved[0][:-1] == row
            assert before <= saved[0][-1] <= after
    finally:
        for con in connections:
            con.close()
