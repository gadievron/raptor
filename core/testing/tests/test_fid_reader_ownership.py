"""Exact FID graph reader components close after transaction exit."""

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
        "index": 0,
        "reader_sha256": "1f53b4d7d1aeb2716781af62f37f068353f954c238dcc95ceddaa6a5aa2f1bce",
        "tail_sha256": "da692901b013042c7ffcdf8eb8ddaeb09d2c98041cc4c3c4e656f9fa2c4eca4b",
    },
    {
        "index": 1,
        "reader_sha256": "91ebb93f24c9784a0bc61b0faced696d07ddada348984fc9c089e94635208325",
        "tail_sha256": "316c474a60abf2a4b1d006b1d37fc3007fd69feac8adced4f5d1a7b198ba5860",
    },
]


def exercise(case, deny, expected_closed, tmp_path):
    root = Path(__file__).resolve().parents[3]
    source = root / "packages/binary_analysis/tests/test_fid_pipeline.py"
    text = source.read_text()
    tree = ast.parse(text)
    cls = next(
        n
        for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == "TestPipelineFids"
    )
    native = next(
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef)
        and n.name == "test_graph_function_nodes_carry_fid"
    )
    blocks = [n for n in native.body if isinstance(n, ast.With)]
    assert len(blocks) == 2
    block = blocks[case["index"]]
    tail = []
    for n in native.body[native.body.index(block) + 1 :]:
        if not isinstance(n, (ast.Assign, ast.Assert)):
            break
        tail.append(n)
    assert (
        hashlib.sha256(ast.get_source_segment(text, block).encode()).hexdigest()
        == case["reader_sha256"]
    )
    assert (
        hashlib.sha256(
            "\n".join(ast.get_source_segment(text, n) for n in tail).encode()
        ).hexdigest()
        == case["tail_sha256"]
    )
    identity = [
        n
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id in ["BUILD_ID", "ANCHOR16"]
            for t in n.targets
        )
    ]
    assert (
        len(identity) == 2
        and hashlib.sha256(
            "\n".join(ast.get_source_segment(text, n) for n in identity).encode()
        ).hexdigest()
        == "235638b2274eb25bd3feca6aab87e0b9063a333e06d77a9d4043ab944448a7b6"
    )
    namespace = {"json": json, "closing": closing}
    exec(
        compile(ast.Module(body=identity, type_ignores=[]), str(source), "exec"),
        namespace,
    )
    producer_text = (root / "packages/binary_analysis/graph_store.py").read_text()
    migration = next(
        n
        for n in ast.parse(producer_text).body
        if isinstance(n, ast.FunctionDef) and n.name == "_migrate"
    )
    scripts = [
        n
        for n in ast.walk(migration)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "executescript"
    ]
    assert len(scripts) == 1
    schema = ast.literal_eval(scripts[0].args[0])
    version_node = next(
        n
        for n in ast.parse(producer_text).body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "SCHEMA_VERSION" for t in n.targets)
    )
    version = ast.literal_eval(version_node.value)
    assert isinstance(version, int) and version > 0
    assert (
        hashlib.sha256(schema.encode()).hexdigest()
        == "d6f85a42db6d7da8d4c67b79022af14950381e16bbcd89241fb72be4a2906c02"
    )
    database = tmp_path / "binary-graph.sqlite"
    with closing(sqlite3.connect(database)) as seed:
        seed.execute("PRAGMA foreign_keys=ON")
        seed.executescript(schema)
        seed.execute(f"PRAGMA user_version={version}")
        seed.execute(
            "INSERT INTO metadata(key,value) VALUES (?,?)",
            ("schema_version", str(version)),
        )
        seed.execute(
            "INSERT INTO snapshots(id,binary_sha256,binary_path,created_at,producer_run) VALUES (?,?,?,?,?)",
            (
                "snapshot",
                "0" * 64,
                str(tmp_path / "sample"),
                "2026-01-01T00:00:00Z",
                str(tmp_path),
            ),
        )
        seed.executemany(
            "INSERT INTO nodes(snapshot_id,id,kind,stable_key,name,address,props_json) VALUES (?,?,?,?,?,?,?)",
            [
                (
                    "snapshot",
                    "function:main",
                    "function",
                    "main",
                    "main",
                    "0x401000",
                    json.dumps({"fid": namespace["ANCHOR16"] + ":0x1000"}),
                ),
                (
                    "snapshot",
                    "function:parse_request",
                    "function",
                    "parse_request",
                    "parse_request",
                    "0x401100",
                    json.dumps({"fid": namespace["ANCHOR16"] + ":0x1100"}),
                ),
                (
                    "snapshot",
                    "binary:sample",
                    "binary",
                    "binary",
                    "sample",
                    "",
                    json.dumps(
                        {
                            "build_id": namespace["BUILD_ID"],
                            "content_anchor": namespace["ANCHOR16"],
                            "image_base": 0x400000,
                            "image_base_recorded": True,
                        }
                    ),
                ),
            ],
        )
        seed.commit()
    before = database.read_bytes()
    connections, denials, events = [], [], []

    def authorize(action, table, *rest):
        if action == sqlite3.SQLITE_READ and table == "nodes":
            denials.append(action)
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
        assert path == database
        con = sqlite3.connect(path, factory=ObservedConnection)
        connections.append(con)
        if deny:
            con.set_authorizer(authorize)
        return con

    namespace.update(
        sqlite3=SimpleNamespace(connect=connect),
        result=SimpleNamespace(graph_path=database),
    )
    refused = False
    try:
        try:
            exec(
                compile(
                    ast.Module(body=[block] + tail, type_ignores=[]),
                    str(source),
                    "exec",
                ),
                namespace,
            )
        except sqlite3.DatabaseError as exc:
            assert exc.sqlite_errorcode == sqlite3.SQLITE_AUTH
            refused = True
        assert refused is deny and bool(denials) is deny
        assert len(connections) == 1 and namespace["conn"] is connections[0]
        try:
            connections[0].execute("SELECT 1")
        except sqlite3.ProgrammingError as exc:
            assert "closed" in str(exc)
            closed = True
        else:
            closed = False
        assert database.read_bytes() == before
        record = {
            "index": case["index"],
            "refused": refused,
            "closed": closed,
            "bytes_unchanged": True,
            "reader_component_only": True,
            "events": list(events),
        }
        (tmp_path / "observation.json").write_text(json.dumps(record, indent=2) + "\n")
        assert closed is expected_closed
        assert events == ["transaction_exit", "close"]
    finally:
        for con in connections:
            con.close()


@pytest.mark.parametrize("case", CASES, ids=lambda row: str(row["index"]))
@pytest.mark.parametrize("deny", [False, True], ids=["normal", "read-refusal"])
def test_fid_reader_closes_after_transaction(case, deny, tmp_path):
    exercise(case, deny, True, tmp_path)
