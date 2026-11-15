"""Exact validation reader ownership components; no ingestion imports."""

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
        "method": "test_reused_ids_bind_only_the_outcomes_target",
        "index": 0,
        "reader_sha256": "e79eb5f5004f033ed1ae56e108f4760a16be154f887adae2c37261d12c18dafe",
        "tail_sha256": "f7af5d982fbe339c73d792c3f6da5ef7264dc4119c34651bb577bfb788c4f432",
        "mode": "targets",
        "id": "targets",
    },
    {
        "method": "test_validation_uses_latest_snapshot_without_historical_fallback",
        "index": 0,
        "reader_sha256": "29ecd6edb46e04128fc8bf24014902d91bf4b98e036863603a09e34c2403c65b",
        "tail_sha256": "9b3391a9e78c31638a09759f2b3b9ecad580ab4ac691fc96cc44b6e3265832b0",
        "mode": "latest",
        "reused_id": True,
        "id": "latest-True",
    },
    {
        "method": "test_validation_uses_latest_snapshot_without_historical_fallback",
        "index": 0,
        "reader_sha256": "29ecd6edb46e04128fc8bf24014902d91bf4b98e036863603a09e34c2403c65b",
        "tail_sha256": "9b3391a9e78c31638a09759f2b3b9ecad580ab4ac691fc96cc44b6e3265832b0",
        "mode": "latest",
        "reused_id": False,
        "id": "latest-False",
    },
    {
        "method": "test_non_understand_producer_identity_still_joins",
        "index": 0,
        "reader_sha256": "726dae5298e4505dee42ef3096e3f05fd8e476798bfaf6d73069c9f665e22d87",
        "tail_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "mode": "lookup",
        "kind": "scan_finding",
        "id": "lookup-scan_finding",
    },
    {
        "method": "test_non_understand_producer_identity_still_joins",
        "index": 0,
        "reader_sha256": "726dae5298e4505dee42ef3096e3f05fd8e476798bfaf6d73069c9f665e22d87",
        "tail_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "mode": "lookup",
        "kind": "codeql_result",
        "id": "lookup-codeql_result",
    },
    {
        "method": "test_non_understand_producer_identity_still_joins",
        "index": 1,
        "reader_sha256": "89e7cad0be6f39fa578f505c190c41014b0fde90d2905a2489ffb6b2721e00f7",
        "tail_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "mode": "edges",
        "id": "edges",
    },
]
SCHEMA_SHA = "10786d74a487c3f08c96707d06b51a20151cf7c29ddfe1b98291e8caaf7aab8f"


def exercise(case, deny, expected_closed, tmp_path):
    source = ROOT / "core/understand_graph/tests/test_validation_ingest_scope.py"
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
    reader = readers[case["index"]]
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
    new_run = tmp_path / "new"
    node_id = "finding"
    with closing(sqlite3.connect(graph)) as seed:
        seed.row_factory = sqlite3.Row
        seed.execute("PRAGMA foreign_keys=ON")
        for name in ("_migrate_1", "_migrate_3", "_migrate_4"):
            schema[name](seed)
        if case["mode"] == "targets":
            subjects = [
                ("first", "understand", str(tmp_path / "run-first")),
                ("second", "understand", str(tmp_path / "run-second")),
            ]
        elif case["mode"] == "latest":
            subjects = [("target", "understand", str(new_run.resolve()))]
        else:
            subjects = [
                (
                    "target",
                    "scan"
                    if case.get("kind", "unchecked_flow") == "scan_finding"
                    else (
                        "codeql"
                        if case.get("kind") == "codeql_result"
                        else "understand"
                    ),
                    str(new_run.resolve()),
                )
            ]
        for index, (target, producer, run) in enumerate(subjects):
            target_path = str(tmp_path / target)
            finding_snapshot, outcome_snapshot = f"finding-{index}", f"outcome-{index}"
            seed.executemany(
                "INSERT INTO snapshots(id,target_path,producer,producer_run) VALUES (?,?,?,?)",
                [
                    (finding_snapshot, target_path, producer, run),
                    (outcome_snapshot, target_path, "validate", run),
                ],
            )
            current_node = node_id if len(subjects) == 1 else f"finding-{index}"
            kind = case.get("kind", "unchecked_flow")
            finding_ref = (
                "NEW-FLOW"
                if case["mode"] == "latest" and not case["reused_id"]
                else "FLOW-1"
            )
            seed.execute(
                "INSERT INTO nodes(id,kind,stable_key,name,snapshot_id) VALUES (?,?,?,?,?)",
                (
                    current_node,
                    kind,
                    kind + "://" + finding_ref,
                    "FLOW-1",
                    finding_snapshot,
                ),
            )
            outcome_node = f"outcome-{index}"
            seed.execute(
                "INSERT INTO nodes(id,kind,stable_key,name,snapshot_id) VALUES (?,?,?,?,?)",
                (
                    outcome_node,
                    "verified_outcome",
                    "verified_outcome://exploitable::FLOW-1",
                    "",
                    outcome_snapshot,
                ),
            )
            if case["mode"] != "latest" or case["reused_id"]:
                seed.execute(
                    "INSERT INTO edges(id,src_id,dst_id,kind,snapshot_id) VALUES (?,?,?,?,?)",
                    (
                        f"edge-{index}",
                        outcome_node,
                        current_node,
                        "VALIDATES",
                        outcome_snapshot,
                    ),
                )
        seed.commit()
        assert seed.execute("PRAGMA foreign_key_check").fetchall() == []
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
        "graph": graph,
        "new_run": new_run,
        "node_id": node_id,
        "kind": case.get("kind"),
        "reused_id": case.get("reused_id"),
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
            if case["mode"] == "lookup":
                assert namespace["node_id"] == node_id and namespace["ref"] == "FLOW-1"
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
def test_validation_reader_closes_after_transaction(tmp_path, case, deny):
    exercise(case, deny, True, tmp_path)
