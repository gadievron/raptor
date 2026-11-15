"""Exact offline DB fixture setup; stop before advisory insertion or queries."""

import __future__
import ast
from contextlib import closing
import copy
import hashlib
import json
import io
import zipfile
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
PINS = {
    "__init__": "ac3320734fc9ff1b6765979b7e5fbfddf2ecfff1ecaf78b41f3725e00d4aacb7",
    "ensure_fresh": "783fbcd142abb0510168f6172f3e7c4a928b11b4665af0a44dcde4856092e347",
    "close": "8e461a9115af3afa45bb666cbc0ff8abfd4e9b8f1f90f3d77474f287193748ce",
    "_init_db": "1fb90685d68a191dc43f4292bdbfe048609c30d9a16ee4e330bf43fbbf18c11f",
    "constants": "3aa13c237628b1fd63bb8f9d0f442500113eda4405bcacf69d9584ef8e4144ca",
    "_ZipServingHttp": "8cf2fd7503e8c0105429580c8ce6e454ae4a6602edf7cc90cb07f29ccfddf857",
    "_make_zip": "9bf0ff9c8d98d74a4ca960a5849857d9e3b3277c764a7510f158326842fb309e",
    "_record": "f69858cd2a7ce813b52e8c70c73677ffa7b4c53cefa1c415e96be2cf440419d2",
    "test_suffixed_debian_record_ingests_and_matches": "051d7321c012793b090f7e74b0ac1a91d1f9ef4f785242438e32af776aab743a",
    "test_wrong_ecosystem_record_still_rejected": "7159315d0fbb36629f8ceb6ea77a10bb8061dc61fe66dfa1bd57506be2f66eda",
    "test_suffixed_query_ecosystem_reads_base_bucket": "d8ecf9d0c492dbd87e73b12a4f165f1a09991ff045d8bb9b4d12fd473527cfae",
    "test_ubuntu_and_gha_ingest_from_their_buckets": "48d25eabc1c84b0b42e39594f8ba37df7371da5db6a79de2a3b224ac0dea4787",
}
CASES = [
    "test_suffixed_debian_record_ingests_and_matches",
    "test_wrong_ecosystem_record_still_rejected",
    "test_suffixed_query_ecosystem_reads_base_bucket",
    "test_ubuntu_and_gha_ingest_from_their_buckets",
]


class SetupBoundary(Exception):
    pass


def exercise(tmp_path, case, deny, expected_closed):
    source = ROOT / "packages/sca/tests/test_osv_offline_matching.py"
    text = source.read_text()
    names = {"_ZipServingHttp", "_make_zip", "_record", case}
    functions = [
        n
        for n in ast.parse(text).body
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names
    ]
    assert len(functions) == 4
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
        and n.name in {"__init__", "_init_db", "close", "ensure_fresh"}
    ]
    assert len(methods) == 4
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
    boundary = SetupBoundary("stop after native schema setup before refresh work")

    class Connection(sqlite3.Connection):
        def commit(self):
            super().commit()
            assert not self.in_transaction
            boundaries.append({"before": database.read_bytes()})
            raise boundary

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
        "io": io,
        "zipfile": zipfile,
        "Path": Path,
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
                namespace[case](tmp_path)
            assert caught.value.sqlite_errorcode == sqlite3.SQLITE_AUTH
            assert denials == ["advisories"] and boundaries == []
        else:
            with pytest.raises(SetupBoundary) as caught:
                namespace[case](tmp_path)
            assert caught.value is boundary
            assert len(boundaries) == 1 and denials == []
        assert len(objects) == len(connections) == 1
        assert objects[0]._http.calls == []
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
                    "case": case,
                    "http_calls": objects[0]._http.calls,
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


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize(
    "deny", [False, True], ids=["setup-boundary", "schema-refusal"]
)
def test_matching_fixture_owns_schema_connection(tmp_path, case, deny):
    exercise(tmp_path, case, deny, True)
