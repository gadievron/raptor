"""Exact unpublished connection component; no native module imports."""

import ast
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
FACTORY_SHA = "31adc4c72b21bafb1a76523faed690974f9c49b9eed8db6d77e2cae5b21430bf"
PROXY_SHA = "7c67eed58f8539b27572e8fea1d2c824c5d1a6989fd5fe3ab7687a7150a122a8"


def exercise(tmp_path, deny, expected_closed):
    source = ROOT / "core/understand_graph/tests/test_backfill_connection_ownership.py"
    text = source.read_text()
    function = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef) and n.name == "_exercise"
    )
    proxy = next(
        n
        for n in function.body
        if isinstance(n, ast.ClassDef) and n.name == "Connection"
    )
    factory = next(
        n
        for n in function.body
        if isinstance(n, ast.FunctionDef) and n.name == "connect"
    )
    for node, pin in [(proxy, PROXY_SHA), (factory, FACTORY_SHA)]:
        assert (
            hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
            == pin
        )
    store = ROOT / "core/understand_graph/store.py"
    migration = next(
        n
        for n in ast.parse(store.read_text()).body
        if isinstance(n, ast.FunctionDef) and n.name == "_migrate_1"
    )
    ddl = ast.literal_eval(migration.body[0].value.args[1])
    assert (
        hashlib.sha256(ddl.encode()).hexdigest()
        == "5a98a75b7cd67e3636812a9c6506d030cbd45768550bfa6f4185448000fcfe7d"
    )
    database = tmp_path / "graph.sqlite"
    blob = json.dumps(
        {"name": "GET /search", "entry": "GET /search", "path": "/search"},
        sort_keys=True,
    )
    with closing(sqlite3.connect(database)) as seed:
        seed.execute("PRAGMA foreign_keys=ON")
        seed.executescript(ddl)
        seed.execute(
            "INSERT INTO snapshots(id,target_path) VALUES (?,?)",
            ("snapshot", str(tmp_path / "target")),
        )
        seed.execute(
            "INSERT INTO nodes(id,kind,stable_key,name,snapshot_id,props_json) VALUES (?,?,?,?,?,?)",
            ("entry", "entry_point", "entry", "GET /search", "snapshot", blob),
        )
        seed.commit()
        assert seed.execute("PRAGMA foreign_key_check").fetchall() == []
    before = database.read_bytes()
    records, events, captured, denials = [], [], [], []

    def acquire(path):
        assert path == database
        connection = sqlite3.connect(path)
        captured.append(connection)
        if deny:

            def authorizer(action, table, column, *_):
                if (
                    action == sqlite3.SQLITE_READ
                    and table == "nodes"
                    and column == "props_json"
                ):
                    denials.append((table, column))
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            connection.set_authorizer(authorizer)
        return connection

    namespace = {
        "sqlite3": SimpleNamespace(connect=acquire),
        "records": records,
        "events": events,
        "stage": "update",
        "error": None,
        "after": True,
        "failure": None,
    }
    exec(
        compile(
            ast.Module(body=[proxy, factory], type_ignores=[]), str(source), "exec"
        ),
        namespace,
    )
    published = None
    try:
        if deny:
            with pytest.raises(sqlite3.DatabaseError) as caught:
                published = namespace["connect"](database)
            assert caught.value.sqlite_errorcode == sqlite3.SQLITE_AUTH
            assert denials == [("nodes", "props_json")]
            assert records == [] and published is None and events == []
        else:
            published = namespace["connect"](database)
            assert isinstance(published, namespace["Connection"])
            assert len(captured) == 1 and published.connection is captured[0]
            assert records == [(captured[0], database, blob)]
            with closing(published) as owned, owned as entered:
                assert entered is published
                assert entered.execute(
                    "SELECT props_json FROM nodes WHERE id='entry'"
                ).fetchone() == (blob,)
            assert events == [("exit", None), ("close", None)]
        assert len(captured) == 1
        connection = captured[0]
        connection_closed = False
        try:
            connection.execute("SELECT 1")
        except sqlite3.ProgrammingError as exc:
            assert "closed" in str(exc)
            connection_closed = True
        assert connection_closed is expected_closed
        assert database.read_bytes() == before
        (tmp_path / "ownership-observation.json").write_text(
            json.dumps(
                {
                    "deny": deny,
                    "closed_before_rescue": connection_closed,
                    "published": published is not None,
                    "record_count": len(records),
                    "denials": denials,
                    "events": events,
                    "database_unchanged": True,
                }
            )
            + "\n"
        )
    finally:
        for connection in captured:
            connection.close()


@pytest.mark.parametrize("deny", [False, True], ids=["handoff", "read-refusal"])
def test_factory_transfers_or_closes_connection(tmp_path, deny):
    exercise(tmp_path, deny, True)
