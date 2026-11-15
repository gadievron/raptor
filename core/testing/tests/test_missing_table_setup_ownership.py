"""Exact missing-table test setup closes SQLite before analysis boundary."""

import ast
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace

import pytest


class AnalyzeBoundary(Exception):
    pass


def exercise(deny, expected_closed, tmp_path):
    source = (
        Path(__file__).resolve().parents[3]
        / "core/dataflow/tests/test_trust_corpus_report.py"
    )
    text = source.read_text()
    node = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef)
        and n.name == "test_missing_table_is_unavailable_read_not_completed_empty_query"
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
        == "79afd398b0d1aad9523851a4885901031be26eff2b010fff4ab966da47712ab9"
    )
    connections, paths, denials, boundaries = [], [], [], []

    def authorize(action, table, *rest):
        if action == sqlite3.SQLITE_CREATE_TABLE and table == "unrelated":
            denials.append(action)
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def connect(path):
        assert path == tmp_path / "no-table.db"
        con = sqlite3.connect(path)
        connections.append(con)
        paths.append(path)
        if deny:
            con.set_authorizer(authorize)
        return con

    def before_analysis(path):
        caller = sys._getframe(1)
        assert caller.f_code is function.__code__
        captured = caller.f_locals["before"]
        assert captured == path.read_bytes() and captured.startswith(
            b"SQLite format 3\x00"
        )
        boundaries.append({"path": path, "bytes": captured})
        raise AnalyzeBoundary()

    namespace = {
        "Path": Path,
        "sqlite3": SimpleNamespace(connect=connect),
        "r": SimpleNamespace(analyze=before_analysis),
    }
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    function = namespace[node.name]
    failed = stopped = False
    try:
        try:
            function(tmp_path)
        except sqlite3.DatabaseError as exc:
            assert exc.sqlite_errorcode == sqlite3.SQLITE_AUTH
            failed = True
        except AnalyzeBoundary:
            stopped = True
        assert failed is deny and stopped is (not deny)
        assert bool(denials) is deny and len(boundaries) == int(not deny)
        assert len(connections) == len(paths) == 1
        try:
            connections[0].execute("SELECT 1")
        except sqlite3.ProgrammingError as exc:
            assert "closed" in str(exc)
            closed = True
        else:
            closed = False
        record = {
            "denied": failed,
            "closed": closed,
            "analysis_boundary_calls": len(boundaries),
            "captured_native_bytes": bool(boundaries),
        }
        (tmp_path / "observation.json").write_text(json.dumps(record, indent=2) + "\n")
        assert closed is expected_closed
        if not deny:
            assert boundaries[0]["path"] == paths[0]
            with closing(sqlite3.connect(paths[0])) as verify:
                assert verify.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall() == [("unrelated",)]
                assert verify.execute("PRAGMA table_info(unrelated)").fetchall() == [
                    (0, "value", "TEXT", 0, None, 0)
                ]
                assert verify.execute("SELECT * FROM unrelated").fetchall() == []
            assert paths[0].read_bytes() == boundaries[0]["bytes"]
    finally:
        for con in connections:
            con.close()


@pytest.mark.parametrize("deny", [False, True], ids=["normal-setup", "schema-refusal"])
def test_missing_table_setup_closes_connection(deny, tmp_path):
    exercise(deny, True, tmp_path)
