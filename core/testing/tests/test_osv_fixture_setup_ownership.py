"""Exact offline DB fixture setup; stop before advisory insertion or queries."""

import __future__
import ast
from contextlib import closing
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
PINS = {
    "record": "6d400c465c380b2b486a683f7c8e2b025ee003e040dd8a4a2621d33862a22dcf",
    "test_offline_database_scopes_matches_and_fixes_to_release": "a7f87791db13289a0a8bd4069502fafd972d13eed3a40dcb5a5ae66346f4b6fd",
    "__init__": "ac3320734fc9ff1b6765979b7e5fbfddf2ecfff1ecaf78b41f3725e00d4aacb7",
    "close": "8e461a9115af3afa45bb666cbc0ff8abfd4e9b8f1f90f3d77474f287193748ce",
    "_init_db": "1fb90685d68a191dc43f4292bdbfe048609c30d9a16ee4e330bf43fbbf18c11f",
    "constants": "3aa13c237628b1fd63bb8f9d0f442500113eda4405bcacf69d9584ef8e4144ca",
}


class SetupBoundary(Exception):
    pass


def exercise(tmp_path, deny, expected_closed):
    source = ROOT / "packages/sca/tests/test_distro_matching.py"
    text = source.read_text()
    names = {"record", "test_offline_database_scopes_matches_and_fixes_to_release"}
    functions = [
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef) and n.name in names
    ]
    assert len(functions) == 2
    for node in functions:
        assert (
            hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
            == PINS[node.name]
        )
    owner_source = ROOT / "packages/sca/osv_offline.py"
    owner_text = owner_source.read_text()
    owner_tree = ast.parse(owner_text)
    cls = next(
        n
        for n in owner_tree.body
        if isinstance(n, ast.ClassDef) and n.name == "OsvOfflineDB"
    )
    methods = [
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef)
        and n.name in {"__init__", "_init_db", "close"}
    ]
    assert len(methods) == 3
    for method in methods:
        assert (
            hashlib.sha256(
                ast.get_source_segment(owner_text, method).encode()
            ).hexdigest()
            == PINS[method.name]
        )
    constants = [
        n
        for n in owner_tree.body
        if isinstance(n, ast.Assign)
        and any(
            isinstance(t, ast.Name)
            and t.id in {"_DEFAULT_TTL", "_BUSY_TIMEOUT_SECONDS"}
            for t in n.targets
        )
    ]
    assert len(constants) == 2
    assert (
        hashlib.sha256(
            "\n".join(ast.get_source_segment(owner_text, n) for n in constants).encode()
        ).hexdigest()
        == PINS["constants"]
    )
    component = copy.deepcopy(cls)
    component.body = copy.deepcopy(methods)
    connections, objects, denials, boundaries = [], [], [], []
    database = tmp_path / "osv.sqlite"
    boundary = SetupBoundary("stop before native advisory INSERT")

    class Connection(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith("INSERT INTO advisories"):
                assert not self.in_transaction
                boundaries.append(
                    {"sql": sql, "args": args, "before": database.read_bytes()}
                )
                raise boundary
            return super().execute(sql, *args)

    def connected(path, **kwargs):
        assert path == str(database)
        connection = sqlite3.connect(path, factory=Connection, **kwargs)
        connections.append(connection)
        if deny:

            def authorize(action, name, *rest):
                if action == sqlite3.SQLITE_CREATE_TABLE and name == "advisories":
                    denials.append(name)
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            connection.set_authorizer(authorize)
        return connection

    owner_namespace = {"sqlite3": SimpleNamespace(connect=connected)}
    exec(
        compile(
            ast.Module(body=[*constants, component], type_ignores=[]),
            str(owner_source),
            "exec",
            flags=__future__.annotations.compiler_flag,
        ),
        owner_namespace,
    )

    def constructed(*args, **kwargs):
        obj = owner_namespace["OsvOfflineDB"](*args, **kwargs)
        objects.append(obj)
        return obj

    namespace = {
        "OsvOfflineDB": constructed,
        "json": json,
        "pytest": pytest,
        "closing": closing,
    }
    exec(
        compile(
            ast.Module(body=functions, type_ignores=[]),
            str(source),
            "exec",
            flags=__future__.annotations.compiler_flag,
        ),
        namespace,
    )
    try:
        if deny:
            with pytest.raises(sqlite3.DatabaseError) as caught:
                namespace["test_offline_database_scopes_matches_and_fixes_to_release"](
                    tmp_path
                )
            assert caught.value.sqlite_errorcode == sqlite3.SQLITE_AUTH
            assert denials == ["advisories"] and boundaries == []
        else:
            with pytest.raises(SetupBoundary) as caught:
                namespace["test_offline_database_scopes_matches_and_fixes_to_release"](
                    tmp_path
                )
            assert caught.value is boundary
            assert len(boundaries) == 1 and denials == []
            expected = namespace["record"]("git", {"Debian:12": "2", "Debian:13": "3"})
            assert boundaries[0]["args"] == (
                ("Debian", "git", expected["id"], json.dumps(expected)),
            )
        assert len(objects) == len(connections) == 1
        closed = False
        try:
            connections[0].execute("SELECT 1")
        except sqlite3.ProgrammingError as exc:
            assert "closed" in str(exc)
            closed = True
        assert closed is expected_closed
        assert objects[0]._conn is (None if expected_closed else connections[0])
        if not deny:
            assert database.read_bytes() == boundaries[0]["before"]
            with closing(sqlite3.connect(database)) as reader:
                assert {
                    row[0]
                    for row in reader.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                } == {"advisories", "ingest_meta"}
                assert reader.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_eco_pkg'"
                ).fetchall() == [("idx_eco_pkg",)]
                assert reader.execute("SELECT * FROM advisories").fetchall() == []
                assert reader.execute("SELECT * FROM ingest_meta").fetchall() == []
        (tmp_path / "ownership-observation.json").write_text(
            json.dumps(
                {
                    "deny": deny,
                    "closed_before_rescue": closed,
                    "owner_cleared": objects[0]._conn is None,
                    "denials": denials,
                    "boundary_calls": len(boundaries),
                    "setup_only": True,
                }
            )
            + "\n"
        )
    finally:
        for connection in connections:
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize(
    "deny", [False, True], ids=["setup-boundary", "schema-refusal"]
)
def test_offline_fixture_owns_schema_connection(tmp_path, deny):
    exercise(tmp_path, deny, True)
