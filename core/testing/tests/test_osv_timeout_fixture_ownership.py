"""Exact configured-timeout fixture ownership, without contention workers."""

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
SPEC = [
    {
        "path": "packages/sca/tests/test_osv_offline.py",
        "pins": {
            "_ZipServingHttp": "76d0196ec55c5571b9c37cb3082477bda904dfd7d723fecb1e5daed7e4b73237",
            "test_connection_waits_out_a_concurrent_ingest": "d993fa781e220c873f84f079431dd3ebd5360039213fca76a81a97357f7e0b16",
        },
        "constant_names": [],
        "constants_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    {
        "path": "packages/sca/osv_offline.py",
        "pins": {
            "__init__": "ac3320734fc9ff1b6765979b7e5fbfddf2ecfff1ecaf78b41f3725e00d4aacb7",
            "close": "8e461a9115af3afa45bb666cbc0ff8abfd4e9b8f1f90f3d77474f287193748ce",
            "_init_db": "1fb90685d68a191dc43f4292bdbfe048609c30d9a16ee4e330bf43fbbf18c11f",
        },
        "constant_names": ["_DEFAULT_TTL", "_BUSY_TIMEOUT_SECONDS"],
        "constants_sha256": "3aa13c237628b1fd63bb8f9d0f442500113eda4405bcacf69d9584ef8e4144ca",
    },
]


def exercise(tmp_path, deny, expected_closed):
    connections, objects, reads, denials = [], [], [], []
    database = tmp_path / "osv.sqlite"

    class Connection(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql == "PRAGMA busy_timeout":
                reads.append(sql)
            return super().execute(sql, *args)

    def connected(path, **kwargs):
        assert path == str(database)
        connection = sqlite3.connect(path, factory=Connection, **kwargs)
        connections.append(connection)
        if deny:

            def authorize(action, name, value, *_):
                if (
                    action == sqlite3.SQLITE_PRAGMA
                    and name == "busy_timeout"
                    and value is None
                ):
                    denials.append((name, value))
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            connection.set_authorizer(authorize)
        return connection

    namespace = {
        "sqlite3": SimpleNamespace(connect=connected),
        "closing": closing,
        "Path": Path,
    }
    for spec in SPEC:
        source = ROOT / spec["path"]
        text = source.read_text()
        tree = ast.parse(text)
        pinned = {
            n.name: n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in spec["pins"]
        }
        assert set(pinned) == set(spec["pins"])
        for name, pin in spec["pins"].items():
            assert (
                hashlib.sha256(
                    ast.get_source_segment(text, pinned[name]).encode()
                ).hexdigest()
                == pin
            )
        constants = [
            n
            for n in tree.body
            if isinstance(n, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id in spec["constant_names"]
                for t in n.targets
            )
        ]
        assert len(constants) == len(spec["constant_names"])
        assert (
            hashlib.sha256(
                "\n".join(ast.get_source_segment(text, n) for n in constants).encode()
            ).hexdigest()
            == spec["constants_sha256"]
        )
        definitions = [
            n
            for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in spec["pins"]
        ]
        if spec["path"] == "packages/sca/osv_offline.py":
            cls = copy.deepcopy(
                next(
                    n
                    for n in tree.body
                    if isinstance(n, ast.ClassDef) and n.name == "OsvOfflineDB"
                )
            )
            cls.body = [
                n
                for n in cls.body
                if isinstance(n, ast.FunctionDef) and n.name in spec["pins"]
            ]
            assert len(cls.body) == 3
            definitions.append(cls)
        exec(
            compile(
                ast.Module(body=[*constants, *definitions], type_ignores=[]),
                str(source),
                "exec",
                flags=__future__.annotations.compiler_flag,
            ),
            namespace,
        )
    component = namespace["OsvOfflineDB"]

    def constructed(*args, **kwargs):
        obj = component(*args, **kwargs)
        objects.append(obj)
        return obj

    namespace["OsvOfflineDB"] = constructed
    try:
        if deny:
            with pytest.raises(sqlite3.DatabaseError) as caught:
                namespace["test_connection_waits_out_a_concurrent_ingest"](tmp_path)
            assert caught.value.sqlite_errorcode == sqlite3.SQLITE_AUTH
            assert denials == [("busy_timeout", None)]
        else:
            namespace["test_connection_waits_out_a_concurrent_ingest"](tmp_path)
            assert denials == []
        assert reads == ["PRAGMA busy_timeout"]
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
        with closing(sqlite3.connect(database)) as reader:
            assert {
                row[0]
                for row in reader.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            } == {"advisories", "ingest_meta"}
            assert reader.execute("SELECT * FROM advisories").fetchall() == []
            assert reader.execute("SELECT * FROM ingest_meta").fetchall() == []
        (tmp_path / "ownership-observation.json").write_text(
            json.dumps(
                {
                    "deny": deny,
                    "closed_before_rescue": closed,
                    "owner_cleared": objects[0]._conn is None,
                    "reads": reads,
                    "denials": denials,
                    "http_calls": objects[0]._http.calls,
                    "original_timeout_predicate_completed": not deny,
                }
            )
            + "\n"
        )
    finally:
        for connection in connections:
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize(
    "deny", [False, True], ids=["configured-timeout", "pragma-refusal"]
)
def test_timeout_fixture_closes_connection(tmp_path, deny):
    exercise(tmp_path, deny, True)
