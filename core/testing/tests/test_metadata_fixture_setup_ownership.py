"""Exact metadata fixtures close connections across supplied schema refusal."""

import ast
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

CASES = [
    {
        "id": "loader",
        "path": "core/dataflow/tests/test_cvefix_loader.py",
        "helper": "_make_db",
        "sha256": "9894eeb924383e4dc91b782d65e725a82881817bb5c79836cde03a5fd4d5f291",
    },
    {
        "id": "walker",
        "path": "core/dataflow/tests/test_cvefix_walk.py",
        "helper": "_make_meta_db",
        "sha256": "d2f65878f9aecd4aab460ac74785a8bb9d79420a1578ea96166d37460ae83366",
    },
]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
@pytest.mark.parametrize("deny_schema", [False, True], ids=["normal", "schema-refusal"])
def test_metadata_fixture_closes_connection(case, deny_schema, tmp_path):
    source = Path(__file__).resolve().parents[3] / case["path"]
    text = source.read_text()
    node = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef) and n.name == case["helper"]
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
        == case["sha256"]
    )
    connections, denials = [], []

    def authorize(action, table, *rest):
        if action == sqlite3.SQLITE_CREATE_TABLE:
            denials.append((action, table))
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def connect(path):
        con = sqlite3.connect(path)
        connections.append(con)
        if deny_schema:
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
            namespace[case["helper"]](tmp_path / "metadata.sqlite")
        except sqlite3.DatabaseError as exc:
            assert exc.sqlite_errorcode == sqlite3.SQLITE_AUTH
            failed = True
        assert failed is deny_schema and bool(denials) is deny_schema
        assert len(connections) == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connections[0].execute("SELECT 1")
        count = 0
        if not deny_schema:
            with closing(sqlite3.connect(tmp_path / "metadata.sqlite")) as verify:
                tables = ["cwe_classification", "fixes", "commits", "repository"]
                assert {
                    x[0]
                    for x in verify.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                } == set(tables)
                counts = [
                    verify.execute("SELECT COUNT(*) FROM " + name).fetchone()[0]
                    for name in tables
                ]
                count = 5 if case["id"] == "loader" else 2
                assert counts == [count] * 4
                saved = verify.execute(
                    "SELECT f.cve_id,c.cwe_id,f.hash,f.repo_url,cm.parents,r.repo_name,r.repo_language FROM fixes f JOIN cwe_classification c ON f.cve_id=c.cve_id JOIN commits cm ON f.hash=cm.hash AND f.repo_url=cm.repo_url JOIN repository r ON f.repo_url=r.repo_url ORDER BY f.hash"
                ).fetchall()
            if case["id"] == "loader":
                expected = [
                    (
                        "CVE-GOOD",
                        "CWE-89",
                        "fix1",
                        "https://github.com/org/py-app",
                        "['par1']",
                        "py-app",
                        "Python",
                    ),
                    (
                        "CVE-PHP",
                        "CWE-89",
                        "fix2",
                        "https://github.com/org/php-app",
                        "['par2']",
                        "php-app",
                        "PHP",
                    ),
                    (
                        "CVE-MERGE",
                        "CWE-78",
                        "fix3",
                        "https://github.com/org/go-app",
                        "['pa', 'pb']",
                        "go-app",
                        "Go",
                    ),
                    (
                        "CVE-GL",
                        "CWE-79",
                        "fix4",
                        "https://gitlab.com/org/x",
                        "['par4']",
                        "x",
                        "Java",
                    ),
                    (
                        "CVE-OTHER",
                        "CWE-476",
                        "fix5",
                        "https://github.com/org/java-app",
                        "['par5']",
                        "java-app",
                        "Java",
                    ),
                ]
            else:
                expected = [
                    (
                        f"CVE-{i}",
                        "CWE-89",
                        f"fix{i}",
                        f"https://github.com/org/app{i}",
                        f"['par{i}']",
                        f"app{i}",
                        "Python",
                    )
                    for i in (1, 2)
                ]
            assert saved == expected
        (tmp_path / "observation.json").write_text(
            json.dumps(
                {
                    "case": case["id"],
                    "denied": failed,
                    "closed": True,
                    "verified_records": count,
                },
                indent=2,
            )
            + "\n"
        )
    finally:
        for con in connections:
            con.close()
