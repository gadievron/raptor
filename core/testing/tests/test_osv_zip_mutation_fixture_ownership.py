"""Exact offline DB fixture setup; stop before advisory insertion or queries."""

import __future__
import builtins
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
    "_ZipServingHttp": "76d0196ec55c5571b9c37cb3082477bda904dfd7d723fecb1e5daed7e4b73237",
    "_make_zip": "f732af7e35826c8e0b292c07919703f0dad5e262ffffe7deeb37f540c902e9c5",
    "_osv": "3299ea1897f88336e8fb589319b4061876d40576b8511ab8cc949f25014a0b9c",
    "test_refused_zip_keeps_existing_advisories": "18251fb3b24c6f82268d6ae3ef63539a576e8a93255ef639616bd35c495215c1",
    "test_ingest_skips_zip_slip_paths": "cb90148df7dc128c65ea701f16b5e3bd3eda8a17b4597fc52cd2af46cb5931c4",
    "test_failed_ingest_rolls_back_and_keeps_existing_advisories": "d5aa6fa2fa0280a7cf83030f0f41703782b5091f729a18a5ef43eacaf31af1cd",
    "test_post_lock_freshness_recheck_failure_releases_the_lock": "759edbc2ea51b5c78002d143b3c1fcb28cb9b27eb1a6a3d6cf4437bae96bab64",
}
CASES = [
    "test_refused_zip_keeps_existing_advisories",
    "test_ingest_skips_zip_slip_paths",
    "test_failed_ingest_rolls_back_and_keeps_existing_advisories",
    "test_post_lock_freshness_recheck_failure_releases_the_lock",
]


class SetupBoundary(Exception):
    pass


def exercise(tmp_path, case, deny, expected_closed):
    source = ROOT / "packages/sca/tests/test_osv_offline.py"
    text = source.read_text()
    names = {"_ZipServingHttp", "_make_zip", "_osv", case}
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

    scoped_imports = []

    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        assert name == "pytest" and not fromlist and level == 0
        scoped_imports.append(name)
        return pytest

    namespace = {
        "OsvOfflineDB": constructed,
        "json": json,
        "pytest": pytest,
        "closing": closing,
        "io": io,
        "zipfile": zipfile,
        "Path": Path,
        "__builtins__": {**vars(builtins), "__import__": importing},
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
        assert scoped_imports == (
            ["pytest"]
            if case == "test_post_lock_freshness_recheck_failure_releases_the_lock"
            else []
        )
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
                    "scoped_pytest_imports": scoped_imports,
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
def test_zip_mutation_fixture_owns_schema_connection(tmp_path, case, deny):
    exercise(tmp_path, case, deny, True)
