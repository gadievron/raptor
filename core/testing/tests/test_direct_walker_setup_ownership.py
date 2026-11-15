"""Exact walker test setup closes connections before supplied dispatch boundary."""

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
        "name": "test_walk_keeps_both_cwes_of_one_commit",
        "sha256": "6df71559e0e32a6e09383d15f7b2eeee8bb52204e368e82ffbafcc4a80d1ed5f",
    },
    {
        "name": "test_promote_updates_only_on_recovery",
        "sha256": "79a295c4ada05ac465c9352febba57351eb6ac81a8ec63af5ca87846f526adb3",
    },
    {
        "name": "test_walk_dedups_same_commit_cwe_across_cves",
        "sha256": "6e041c43307c5722911d86815702e5aa2cd9f0477625c6322931fcbf9ecf847a",
    },
]


class SetupBoundary(Exception):
    pass


def exercise(case, deny, expected_closed, tmp_path):
    root = Path(__file__).resolve().parents[3]
    source = root / "core/dataflow/tests/test_cvefix_walk.py"
    text = source.read_text()
    node = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef) and n.name == case["name"]
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
        == case["sha256"]
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
    connections, paths, denials, boundaries = [], [], [], []

    def authorize(action, *rest):
        if action == sqlite3.SQLITE_CREATE_TABLE:
            denials.append(action)
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def connect(path):
        assert Path(path).is_relative_to(tmp_path)
        con = sqlite3.connect(path)
        connections.append(con)
        paths.append(Path(path))
        if deny:
            con.set_authorizer(authorize)
        return con

    consumer = SimpleNamespace(_SCHEMA=schema)

    class StopBeforeDispatch:
        def setattr(self, module, name, replacement, **kwargs):
            assert (
                module is consumer and name == "process_pair" and callable(replacement)
            )
            boundaries.append(name)
            raise SetupBoundary()

    namespace = {
        "Path": Path,
        "sqlite3": SimpleNamespace(connect=connect),
        "cvefix_walk": consumer,
    }
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    failed = stopped = False
    try:
        try:
            namespace[case["name"]](StopBeforeDispatch(), tmp_path)
        except sqlite3.DatabaseError as exc:
            assert exc.sqlite_errorcode == sqlite3.SQLITE_AUTH
            failed = True
        except SetupBoundary:
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
        (tmp_path / "observation.json").write_text(
            json.dumps(
                {
                    "case": case["name"],
                    "denied": failed,
                    "closed": closed,
                    "dispatch_boundary_calls": len(boundaries),
                },
                indent=2,
            )
            + "\n"
        )
        assert closed is expected_closed
        if not deny:
            with closing(sqlite3.connect(paths[0])) as verify:
                if case["name"] == "test_promote_updates_only_on_recovery":
                    saved = verify.execute(
                        "SELECT * FROM walk_results ORDER BY fix_hash"
                    ).fetchall()
                    expected = [
                        (
                            fix,
                            "CVE-" + fix,
                            cwe,
                            "Java",
                            "https://github.com/o/a",
                            fix + "p",
                            "ok",
                            before,
                            0,
                            0.0,
                        )
                        for fix, cwe, before in [
                            ("f1", "CWE-89", 0),
                            ("f2", "CWE-79", 0),
                            ("f3", "CWE-22", 2),
                        ]
                    ]
                    assert saved == expected
                else:
                    counts = [
                        verify.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                        for table in [
                            "cwe_classification",
                            "fixes",
                            "commits",
                            "repository",
                        ]
                    ]
                    saved = verify.execute(
                        "SELECT f.cve_id,c.cwe_id,f.hash,f.repo_url,cm.parents,r.repo_language FROM fixes f JOIN cwe_classification c ON f.cve_id=c.cve_id JOIN commits cm ON f.hash=cm.hash AND f.repo_url=cm.repo_url JOIN repository r ON f.repo_url=r.repo_url ORDER BY f.cve_id,c.cwe_id"
                    ).fetchall()
                    if case["name"] == "test_walk_keeps_both_cwes_of_one_commit":
                        assert counts == [2, 1, 1, 1]
                        expected = [
                            (
                                "CVE-1",
                                cwe,
                                "fixA",
                                "https://github.com/org/app",
                                "['parA']",
                                "Python",
                            )
                            for cwe in ["CWE-79", "CWE-89"]
                        ]
                    else:
                        assert counts == [2, 2, 1, 1]
                        expected = [
                            (
                                cve,
                                "CWE-89",
                                "fixA",
                                "https://github.com/org/app",
                                "['parA']",
                                "Python",
                            )
                            for cve in ["CVE-1", "CVE-2"]
                        ]
                    assert saved == expected
    finally:
        for con in connections:
            con.close()


@pytest.mark.parametrize("case", CASES, ids=lambda row: row["name"])
@pytest.mark.parametrize("deny", [False, True], ids=["normal-setup", "schema-refusal"])
def test_direct_setup_closes_connection(case, deny, tmp_path):
    exercise(case, deny, True, tmp_path)
