"""Exact SQLite reader components retire connections after transaction exit."""

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
        "id": "0",
        "path": "core/dataflow/tests/test_cvefix_walk.py",
        "method": "test_walk_records_and_resumes",
        "reader_sha256": "79f78ff12f0146a04b43a2119d41ff209b90a77c0f94d0f537d837d64dce22f5",
        "tail_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    {
        "id": "1",
        "path": "core/dataflow/tests/test_cvefix_walk.py",
        "method": "test_walk_keeps_both_cwes_of_one_commit",
        "reader_sha256": "5590a49b772a3f96f91cd790ddb7ff5085ca5d0bfb7d1eab414a74f3c3e869f4",
        "tail_sha256": "2fcaec32d5d0d4e62388f1430a41d42077fa3750ae9c50f93dfb52fec202b1a0",
    },
    {
        "id": "2",
        "path": "core/dataflow/tests/test_cvefix_walk.py",
        "method": "test_promote_updates_only_on_recovery",
        "reader_sha256": "5f7f53f5302b420ae9726064d098656fa384ce7af2eb6c28f378a6f9145af1be",
        "tail_sha256": "cf2ae908dc29d4152dc2cedca3f8512016fc59f64e34b88b5d38ec2a4cbc4194",
    },
    {
        "id": "3",
        "path": "core/dataflow/tests/test_cvefix_walk.py",
        "method": "test_walk_limit",
        "reader_sha256": "3fb503df36734021dcabdad37bab2849c9db95d2a0dc3426599b05c8428ef2e1",
        "tail_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    {
        "id": "4",
        "path": "core/dataflow/tests/test_cvefix_bridge.py",
        "method": "test_synthesize_from_results_aggregates_persists_resumes",
        "reader_sha256": "9ef7f673eba76a9af816079db9de262634eabd6cd94458d20337cee2f29f8bfb",
        "tail_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    {
        "id": "5",
        "path": "core/dataflow/tests/test_cvefix_bridge.py",
        "method": "test_synthesize_from_results_crash_isolation",
        "reader_sha256": "849eacd5304e4562fb280f6a1fd098cf4ad743998c5be6f3040eec4b71498f99",
        "tail_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
]


def exercise(case, deny, expected_closed, tmp_path):
    root = Path(__file__).resolve().parents[3]
    source = root / case["path"]
    text = source.read_text()
    native = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef) and n.name == case["method"]
    )
    blocks = [n for n in native.body if isinstance(n, ast.With)]
    assert len(blocks) == 1
    block = blocks[0]
    tail_assertions = []
    for statement in native.body[native.body.index(block) + 1 :]:
        if not isinstance(statement, ast.Assert):
            break
        tail_assertions.append(statement)
    assert (
        hashlib.sha256(
            "\n".join(ast.get_source_segment(text, a) for a in tail_assertions).encode()
        ).hexdigest()
        == case["tail_sha256"]
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, block).encode()).hexdigest()
        == case["reader_sha256"]
    )
    walker = "walk.py" in case["path"]
    producer = root / (
        "core/dataflow/cvefix_walk.py" if walker else "core/dataflow/cvefix_bridge.py"
    )
    pt = producer.read_text()
    schema = next(
        n
        for n in ast.parse(pt).body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_SCHEMA" for t in n.targets)
    )
    schema_text = ast.literal_eval(schema.value)
    graph = tmp_path / "results.sqlite"
    method = case["method"]
    with closing(sqlite3.connect(graph)) as seed:
        seed.execute(schema_text)
        if walker:

            def row(fix, cwe="CWE-89", before=2, after=1):
                return (
                    fix,
                    "CVE-" + fix,
                    cwe,
                    "Python",
                    "https://github.com/org/app",
                    "par",
                    "ok",
                    before,
                    after,
                    0.0,
                )

            if "both_cwes" in method:
                rows = [row("fixA", cwe, 1, 1) for cwe in ["CWE-89", "CWE-79"]]
            elif "promote" in method:
                rows = [
                    (
                        "f1",
                        "CVE-f1",
                        "CWE-89",
                        "Java",
                        "https://github.com/o/a",
                        "f1p",
                        "ok_built",
                        5,
                        3,
                        0.0,
                    ),
                    (
                        "f2",
                        "CVE-f2",
                        "CWE-79",
                        "Java",
                        "https://github.com/o/a",
                        "f2p",
                        "ok",
                        0,
                        0,
                        0.0,
                    ),
                    (
                        "f3",
                        "CVE-f3",
                        "CWE-22",
                        "Java",
                        "https://github.com/o/a",
                        "f3p",
                        "ok",
                        2,
                        0,
                        0.0,
                    ),
                ]
            elif "limit" in method:
                rows = [row("fix1", before=0, after=0)]
            else:
                rows = [row("fix1"), row("fix2")]
            seed.executemany(
                "INSERT INTO walk_results VALUES (?,?,?,?,?,?,?,?,?,?)", rows
            )
        else:
            if "aggregates" in method:
                rows = [
                    (
                        "f1",
                        "CWE-89",
                        "CVE-f1",
                        "Python",
                        "f1:id",
                        "sound",
                        "smt",
                        "smt:charset:[a-z]+@x:1",
                        "tier0 unsat",
                        0.0,
                    ),
                    (
                        "f2",
                        "CWE-79",
                        "CVE-f2",
                        "Python",
                        "f2:id",
                        "not_sound",
                        "codeql",
                        "QL2",
                        "suppress_fp_failed(after=2)",
                        0.0,
                    ),
                    (
                        "f3",
                        "CWE-78",
                        "CVE-f3",
                        "Python",
                        None,
                        "build_fail",
                        "",
                        None,
                        "",
                        0.0,
                    ),
                ]
            else:
                rows = [
                    (
                        "f1",
                        "CWE-89",
                        "CVE-f1",
                        "Python",
                        "f1:id",
                        "sound",
                        "codeql",
                        "QL",
                        "",
                        0.0,
                    ),
                    (
                        "f2",
                        "CWE-79",
                        "CVE-f2",
                        "Python",
                        None,
                        "error",
                        "",
                        None,
                        "codeql exploded",
                        0.0,
                    ),
                    (
                        "f3",
                        "CWE-78",
                        "CVE-f3",
                        "Python",
                        "f3:id",
                        "sound",
                        "codeql",
                        "QL",
                        "",
                        0.0,
                    ),
                ]
            seed.executemany(
                "INSERT INTO synth_results VALUES (?,?,?,?,?,?,?,?,?,?)", rows
            )
        seed.commit()
    before = graph.read_bytes()
    connections, denials, events = [], [], []
    table = "walk_results" if walker else "synth_results"

    def authorize(action, name, *rest):
        if action == sqlite3.SQLITE_READ and name == table:
            denials.append((action, name))
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    class ObservedConnection(sqlite3.Connection):
        def __exit__(self, *exc):
            try:
                return super().__exit__(*exc)
            finally:
                events.append("transaction_exit")

        def close(self):
            super().close()
            events.append("close")

    def connect(path):
        assert Path(path) == graph
        con = sqlite3.connect(path, factory=ObservedConnection)
        connections.append(con)
        if deny:
            con.set_authorizer(authorize)
        return con

    namespace = {
        "sqlite3": SimpleNamespace(connect=connect),
        "results": graph,
        "synth": graph,
        "closing": closing,
    }
    refused = False
    try:
        try:
            exec(
                compile(
                    ast.Module(body=[block] + tail_assertions, type_ignores=[]),
                    str(source),
                    "exec",
                ),
                namespace,
            )
        except sqlite3.DatabaseError as exc:
            assert exc.sqlite_errorcode == sqlite3.SQLITE_AUTH
            refused = True
        assert refused is deny and bool(denials) is deny
        assert len(connections) == 1 and namespace["con"] is connections[0]
        try:
            connections[0].execute("SELECT 1")
        except sqlite3.ProgrammingError as exc:
            assert "closed" in str(exc)
            closed = True
        else:
            closed = False
        assert graph.read_bytes() == before
        record = {
            "case": case["id"],
            "refused": refused,
            "closed": closed,
            "exact_component": True,
            "bytes_unchanged": True,
            "events": list(events),
        }
        (tmp_path / "observation.json").write_text(json.dumps(record, indent=2) + "\n")
        assert closed is expected_closed
        assert events == ["transaction_exit", "close"]
    finally:
        for con in connections:
            con.close()


@pytest.mark.parametrize("case", CASES, ids=lambda row: row["id"])
@pytest.mark.parametrize("deny", [False, True], ids=["normal", "read-refusal"])
def test_reader_component_retires_connection(case, deny, tmp_path):
    exercise(case, deny, True, tmp_path)
