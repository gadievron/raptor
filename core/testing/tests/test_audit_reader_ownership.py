"""Exact audit SQLite reader components retire connections after transaction exit."""

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
        "path": "core/audit/tests/test_cross_entry_includes.py",
        "method": "test_header_changes_invalidate_delivered_context_without_widening_catalogue",
        "reader_sha256": "fb487007af45ae4a81f1e21d21adc1566e8d4d2f85ca846beb24b34949c500a9",
    },
    {
        "id": "1",
        "path": "core/audit/tests/test_cross_entry_delivery_work.py",
        "method": "test_large_context_batch_uses_lookup_and_keeps_exact_receipts",
        "reader_sha256": "fbdcde204132238f24f168636d4f5143decfdc251f5cd46b184b5591c159704e",
    },
    {
        "id": "2",
        "path": "core/audit/tests/test_cross_entry_delivery_work.py",
        "method": "test_nullable_legacy_job_ids_keep_original_shadow_passes",
        "reader_sha256": "18914827fcb283c8a18b58da692d38c961dbf7fbbc5093af4902541fba379060",
    },
]
SCHEMA_PINS = [
    {
        "source": "core/audit/cross_entry/catalogue.py",
        "class": "Catalogue",
        "schema_sha256": "f9854e4e7e96d512c29f3352b9d96328a570aa921d84f112493feeadab60213f",
    },
    {
        "source": "core/audit/cross_entry/progress.py",
        "class": "WorkQueue",
        "schema_sha256": "b723e4dd5b66addfe242d4bbb8bce54a6625814c04a71736de8b4047b1519cc4",
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
    block = next(n for n in native.body if isinstance(n, ast.With))
    assert (
        hashlib.sha256(ast.get_source_segment(text, block).encode()).hexdigest()
        == case["reader_sha256"]
    )
    catalogue_case = case["id"] == "0"
    schema_case = SCHEMA_PINS[0 if catalogue_case else 1]
    producer_text = (root / schema_case["source"]).read_text()
    cls = next(
        n
        for n in ast.parse(producer_text).body
        if isinstance(n, ast.ClassDef) and n.name == schema_case["class"]
    )
    init = next(
        n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__"
    )
    calls = [
        n
        for n in ast.walk(init)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "executescript"
    ]
    assert len(calls) == 1
    schema = ast.literal_eval(calls[0].args[0])
    assert hashlib.sha256(schema.encode()).hexdigest() == schema_case["schema_sha256"]
    out = tmp_path / "out"
    out.mkdir()
    database = out / (
        "catalogue.sqlite" if catalogue_case else "cross-entry-work.sqlite"
    )
    receipts, functions, lookup = {}, {}, {}
    with closing(sqlite3.connect(database)) as seed:
        seed.executescript(schema)
        if catalogue_case:
            fixture_source = root / "core/audit/tests/test_cross_entry.py"
            ft = fixture_source.read_text()
            node = next(
                n
                for n in ast.parse(ft).body
                if isinstance(n, ast.FunctionDef) and n.name == "dispatch_sources"
            )
            assert (
                hashlib.sha256(ast.get_source_segment(ft, node).encode()).hexdigest()
                == "ad5b8be9c2da382e2cf3175383254cb1f0063f10b7838a7f19e0663dd0590542"
            )
            paths = [
                name for name in ast.literal_eval(node.body[0].value) if name != "api.h"
            ]
            assert set(paths) == {"setup.c", "invoke.c", "consumer.c"}
            seed.executemany(
                "INSERT INTO files(path) VALUES (?)", [(name,) for name in paths]
            )
        elif case["id"] == "1":
            for i in range(18):
                consumer, job, evidence = f"function{i}", f"job{i}", f"evidence{i}"
                seed.execute(
                    "INSERT INTO jobs(namespace,view_id,id,consumer,status,result) VALUES (?,?,?,?,?,?)",
                    (
                        "main",
                        "view",
                        job,
                        consumer,
                        "prepared",
                        json.dumps({"key": evidence}),
                    ),
                )
                receipts[f"a.c:get{i}"] = {
                    "namespace": "main",
                    "view": "view",
                    "job": job,
                    "evidence": evidence,
                }
                functions[consumer] = {"name": f"get{i}"}
                lookup[job] = {"evidence": evidence}
            assert len(receipts) == len(functions) == len(lookup) == 18
        else:
            seed.executemany(
                "INSERT INTO acknowledgements(namespace,view_id,job_id,evidence) VALUES (?,?,?,?)",
                [("main", "view", None, f"legacy{i % 3}") for i in range(9)],
            )
        seed.commit()
    before = database.read_bytes()
    connections, denials, events = [], [], []
    target_table = (
        "files"
        if catalogue_case
        else "jobs"
        if case["id"] == "1"
        else "acknowledgements"
    )

    def authorize(action, table, *rest):
        if action == sqlite3.SQLITE_READ and table == target_table:
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
        assert Path(path) == database
        con = sqlite3.connect(path, factory=ObservedConnection)
        connections.append(con)
        if deny:
            con.set_authorizer(authorize)
        return con

    namespace = {
        "sqlite3": SimpleNamespace(connect=connect, Row=sqlite3.Row),
        "closing": closing,
        "catalogue": str(database),
        "out": out,
        "receipts": receipts,
        "functions": functions,
        "indexed": [lookup],
    }
    refused = False
    try:
        try:
            exec(
                compile(ast.Module(body=[block], type_ignores=[]), str(source), "exec"),
                namespace,
            )
        except sqlite3.DatabaseError as exc:
            assert exc.sqlite_errorcode == sqlite3.SQLITE_AUTH
            refused = True
        assert refused is deny and bool(denials) is deny
        assert len(connections) == 1 and namespace["db"] is connections[0]
        try:
            connections[0].execute("SELECT 1")
        except sqlite3.ProgrammingError as exc:
            assert "closed" in str(exc)
            closed = True
        else:
            closed = False
        assert database.read_bytes() == before
        record = {
            "case": case["id"],
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


@pytest.mark.parametrize("case", CASES, ids=lambda row: row["id"])
@pytest.mark.parametrize("deny", [False, True], ids=["normal", "read-refusal"])
def test_audit_reader_closes_after_transaction(case, deny, tmp_path):
    exercise(case, deny, True, tmp_path)
