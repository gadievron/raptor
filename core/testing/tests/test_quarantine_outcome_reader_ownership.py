"""Exact graph reader components own connections after transaction exit."""

import ast
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

ROOT = Path(__file__).resolve().parents[3]
CASES = [
    {
        "path": "core/project/tests/test_import_graph_quarantine.py",
        "method": "test_graph_rebuild_uses_run_json_without_replaying_quarantined_outcomes",
        "reader_sha256": "c3cc87ed69da13cddbd6774450a1c41372c7bff0c1b84da0c368ea52b5450f63",
        "tail_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "id": "quarantined",
    },
    {
        "path": "core/project/tests/test_import_graph_quarantine.py",
        "method": "test_local_validation_inputs_remain_rebuildable",
        "reader_sha256": "bf22d46b0a195cc5edbf2deb116e2be58c9fcbfa051729ddd182a78bbaef6bdb",
        "tail_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "id": "local",
    },
    {
        "path": "packages/exploitability_validation/tests/test_validation_outcomes_writer.py",
        "method": "test_written_outcomes_are_ingestable",
        "reader_sha256": "32d0615611b1e2224e68348976711b1dd5251268edfe4324a0e6f50299b513e2",
        "tail_sha256": "5871ae0f70dc1617941d7a310000b9acb8c90c16ae52177bd493686ed1d2e9ad",
        "id": "writer",
    },
]
SCHEMA_SHA = "10786d74a487c3f08c96707d06b51a20151cf7c29ddfe1b98291e8caaf7aab8f"


def exercise(case, deny, expected_closed, tmp_path):
    source = ROOT / case["path"]
    text = source.read_text()
    method = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef) and n.name == case["method"]
    )
    readers = [
        n
        for n in method.body
        if isinstance(n, ast.With)
        and any(
            isinstance(a, ast.Call)
            and isinstance(a.func, ast.Name)
            and a.func.id == "open_graph"
            for a in ast.walk(n)
        )
    ]
    assert len(readers) == 1
    reader = readers[0]
    tail = []
    for node in method.body[method.body.index(reader) + 1 :]:
        if not isinstance(node, (ast.Assign, ast.Assert)):
            break
        tail.append(node)
    assert (
        hashlib.sha256(ast.get_source_segment(text, reader).encode()).hexdigest()
        == case["reader_sha256"]
    )
    assert (
        hashlib.sha256(
            "\n".join(ast.get_source_segment(text, n) for n in tail).encode()
        ).hexdigest()
        == case["tail_sha256"]
    )
    store = ROOT / "core/understand_graph/store.py"
    store_text = store.read_text()
    schema_names = {"_execute_statements", "_migrate_1", "_migrate_3", "_migrate_4"}
    schema_nodes = [
        n
        for n in ast.parse(store_text).body
        if isinstance(n, ast.FunctionDef) and n.name in schema_names
    ]
    assert len(schema_nodes) == 4
    assert (
        hashlib.sha256(
            "\n".join(
                ast.get_source_segment(store_text, n) for n in schema_nodes
            ).encode()
        ).hexdigest()
        == SCHEMA_SHA
    )
    schema = {"sqlite3": sqlite3}
    exec(
        compile(ast.Module(body=schema_nodes, type_ignores=[]), str(store), "exec"),
        schema,
    )
    graph = tmp_path / "graph.sqlite"
    kind = "entry_point" if case["id"] == "quarantined" else "verified_outcome"
    producer = "understand" if kind == "entry_point" else "validate"
    with closing(sqlite3.connect(graph)) as seed:
        seed.row_factory = sqlite3.Row
        seed.execute("PRAGMA foreign_keys=ON")
        for name in ("_migrate_1", "_migrate_3", "_migrate_4"):
            schema[name](seed)
        seed.execute(
            "INSERT INTO snapshots(id,target_path,producer,producer_run) VALUES (?,?,?,?)",
            ("snapshot", str(tmp_path / "target"), producer, str(tmp_path / "run")),
        )
        seed.execute(
            "INSERT INTO nodes(id,kind,stable_key,name,snapshot_id,props_json) VALUES (?,?,?,?,?,?)",
            (
                "node",
                kind,
                kind + "://owned",
                "GET /search" if kind == "entry_point" else "exploitable",
                "snapshot",
                json.dumps(
                    {"name": "GET /search"}
                    if kind == "entry_point"
                    else {"status": "exploitable", "finding_id": "FINDING-1"}
                ),
            ),
        )
        seed.commit()
        assert seed.execute("PRAGMA foreign_key_check").fetchall() == []
        assert [
            tuple(row) for row in seed.execute("SELECT kind,snapshot_id FROM nodes")
        ] == [(kind, "snapshot")]
        assert [row[0] for row in seed.execute("SELECT producer FROM snapshots")] == [
            producer
        ]
    before = graph.read_bytes()
    connections, events, denials = [], [], []

    class Connection(sqlite3.Connection):
        def __exit__(self, *args):
            events.append("transaction_exit")
            return super().__exit__(*args)

        def close(self):
            super().close()
            events.append("close")

    def opened(path):
        assert path == graph
        connection = sqlite3.connect(path, factory=Connection)
        connections.append(connection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        if deny:

            def authorize(action, table, column, *_):
                if action == sqlite3.SQLITE_READ:
                    denials.append((table, column))
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            connection.set_authorizer(authorize)
        return connection

    namespace = {
        "open_graph": opened,
        "closing": closing,
        "rebuilt": graph,
        "graph_path": graph,
    }
    body = compile(
        ast.Module(body=[reader, *tail], type_ignores=[]), str(source), "exec"
    )
    try:
        if deny:
            with pytest.raises(sqlite3.DatabaseError) as caught:
                exec(body, namespace)
            assert caught.value.sqlite_errorcode == sqlite3.SQLITE_AUTH
            assert denials
        else:
            exec(body, namespace)
        assert len(connections) == 1
        closed = False
        try:
            connections[0].execute("SELECT 1")
        except sqlite3.ProgrammingError as exc:
            assert "closed" in str(exc)
            closed = True
        assert closed is expected_closed
        assert events == (
            ["transaction_exit", "close"] if expected_closed else ["transaction_exit"]
        )
        assert graph.read_bytes() == before
        (tmp_path / "ownership-observation.json").write_text(
            json.dumps(
                {
                    "case": case["id"],
                    "deny": deny,
                    "closed_before_rescue": closed,
                    "events": events,
                    "denials": denials,
                    "database_unchanged": True,
                }
            )
            + "\n"
        )
    finally:
        for connection in connections:
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
@pytest.mark.parametrize("deny", [False, True], ids=["normal", "read-refusal"])
def test_graph_readers_close_after_transaction(tmp_path, case, deny):
    exercise(case, deny, True, tmp_path)
