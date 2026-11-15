"""Exact offline fixture closes its first connection before a lazy reconnect."""

import __future__
import ast
import builtins
from contextlib import closing
import copy
import hashlib
import json
import logging
from pathlib import Path
import re
import sqlite3
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
SPEC = [
    {
        "path": "packages/sca/tests/test_osv_offline.py",
        "pins": {
            "_ZipServingHttp": "76d0196ec55c5571b9c37cb3082477bda904dfd7d723fecb1e5daed7e4b73237",
            "test_close_releases_connection": "76f2e29198336ab6f79cb71853b0b276cecfb567f59027e0def2c4169ddf3e04",
        },
        "constant_names": [],
        "constants_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    {
        "path": "packages/sca/osv_offline.py",
        "pins": {
            "_storage_ecosystem": "df4679e684e8ac9e8e40c2a82f76c1cb7aca7d3eb059995a5f97b6cb945b8398",
            "__init__": "ac3320734fc9ff1b6765979b7e5fbfddf2ecfff1ecaf78b41f3725e00d4aacb7",
            "ensure_fresh": "783fbcd142abb0510168f6172f3e7c4a928b11b4665af0a44dcde4856092e347",
            "query": "582f9bd3a53bea265dcec093a6db037b6d914c72e29d4c3f8566f30f0082f353",
            "close": "8e461a9115af3afa45bb666cbc0ff8abfd4e9b8f1f90f3d77474f287193748ce",
            "_init_db": "1fb90685d68a191dc43f4292bdbfe048609c30d9a16ee4e330bf43fbbf18c11f",
            "_lookup_rows": "f041ebf34ae60373be2fa15b8b8e4c4093c37f104ed5826811b5c86163463d67",
        },
        "constant_names": ["_DEFAULT_TTL", "_BUSY_TIMEOUT_SECONDS", "_BUCKET_NAME"],
        "constants_sha256": "dc0d7c6917195cd761d966fe3ecd762e86ed1f6bdbb3207455db747f0ee29c92",
    },
    {
        "path": "packages/sca/ecosystems.py",
        "pins": {
            "distro_base": "973d1e0da1e801f8da03ffe12accb2818960ffb1880d4b442bf9d7fe30a534d4"
        },
        "constant_names": ["DISTRO_ECOSYSTEM_BASES"],
        "constants_sha256": "375ac6aabf58b7f9f83e87f406d09ecebf874b812dd6a20fe10dd33b03b783af",
    },
    {
        "path": "packages/sca/osv.py",
        "pins": {
            "_canonical_name": "c8d4f6d5d612278da0ce9a40a84aac9a9eb9af6f02f150f9e8e30b46f45808d6",
            "_gha_parent_repo": "8b14a5cffead18ccb7baad28409fe24d3cd7290c26f43d1acc4903400ba576b8",
        },
        "constant_names": [],
        "constants_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    {
        "path": "packages/sca/naming.py",
        "pins": {
            "pep503_name": "e078d26e69e9bf068947a7feec1e20757978c392c8da5588f50f0e0abd6d4b95",
            "fold_name": "77e67f425d145ab7df80d9fed8b31daba4c426f7b315e0ab5c0bad934bb8326b",
        },
        "constant_names": ["_PEP503_RUNS_RE"],
        "constants_sha256": "d5607076871f6a32d6bbff8425b1bc60b89043867e55443f37947104033a5841",
    },
    {
        "path": "core/oci/distro.py",
        "pins": {
            "context_error": "26b0c3cc0007c5737bcc7a18532dc0d70847778716379c36655566785048e568"
        },
        "constant_names": ["_UBUNTU_LTS"],
        "constants_sha256": "7c422f50e0758e2be54ae244298858613bf08a5a971fa44bacfb90bb8555282b",
    },
]


def exercise(tmp_path, deny, expected_closed):
    connections, objects, events, imports, lookups, denials = [], [], [], [], [], []
    database = tmp_path / "osv.sqlite"
    logger = logging.Logger("owned.osv.reconnect", logging.CRITICAL)
    logger.manager = logging.Manager(logging.RootLogger(logging.CRITICAL))
    namespace = {
        "re": re,
        "Path": Path,
        "closing": closing,
        "logger": logger,
        "__package__": "packages.sca",
    }

    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        assert (
            name == "ecosystems" and level == 1 and tuple(fromlist) == ("distro_base",)
        )
        imports.append((name, level, tuple(fromlist)))
        return SimpleNamespace(distro_base=namespace["distro_base"])

    namespace["__builtins__"] = {**vars(builtins), "__import__": importing}

    class Connection(sqlite3.Connection):
        def close(self):
            super().close()
            events.append(("close", self.ordinal))

        def execute(self, sql, *args):
            if sql.startswith("SELECT json FROM advisories"):
                lookups.append((self.ordinal, sql, args))
            return super().execute(sql, *args)

    def is_closed(connection):
        try:
            connection.execute("SELECT 1")
        except sqlite3.ProgrammingError as exc:
            assert "closed" in str(exc)
            return True
        return False

    def connected(path, **kwargs):
        assert path == str(database) and len(objects) == 1
        ordinal = len(connections)
        assert ordinal in (0, 1)
        assert objects[0]._conn is None
        if ordinal == 1:
            assert is_closed(connections[0])
            assert events == [("open", 0), ("close", 0)]
        connection = sqlite3.connect(path, factory=Connection, **kwargs)
        connection.ordinal = ordinal
        connections.append(connection)
        events.append(("open", ordinal))
        if deny and ordinal == 1:

            def authorize(action, table, column, *_):
                if (
                    action == sqlite3.SQLITE_READ
                    and table == "advisories"
                    and column == "json"
                ):
                    denials.append((table, column))
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            connection.set_authorizer(authorize)
        return connection

    namespace["sqlite3"] = SimpleNamespace(connect=connected)
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
                isinstance(z, ast.Name) and z.id in spec["constant_names"]
                for z in n.targets
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
            assert len(cls.body) == 6
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
                namespace["test_close_releases_connection"](tmp_path)
            assert caught.value.sqlite_errorcode == sqlite3.SQLITE_AUTH
            assert denials == [("advisories", "json")]
        else:
            namespace["test_close_releases_connection"](tmp_path)
            assert denials == []
        assert len(connections) == 2 and connections[0] is not connections[1]
        assert (
            is_closed(connections[0]) and is_closed(connections[1]) is expected_closed
        )
        assert objects[0]._conn is (None if expected_closed else connections[1])
        assert objects[0]._http.calls == []
        assert imports == [("ecosystems", 1, ("distro_base",))] * 2
        assert (
            len(lookups) == 1
            and lookups[0][0] == 1
            and lookups[0][2] == (("PyPI", "x"),)
        )
        expected_events = [("open", 0), ("close", 0), ("open", 1)]
        if expected_closed:
            expected_events.append(("close", 1))
        assert events == expected_events
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
                    "first_closed_before_reconnect": True,
                    "second_closed_before_rescue": expected_closed,
                    "owner_cleared": objects[0]._conn is None,
                    "http_calls": objects[0]._http.calls,
                    "events": events,
                    "lookups": lookups,
                    "denials": denials,
                    "original_empty_query_assertion_completed": not deny,
                }
            )
            + "\n"
        )
    finally:
        for connection in connections:
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize(
    "deny", [False, True], ids=["empty-query", "reopened-read-refusal"]
)
def test_reconnected_fixture_retires_both_connections(tmp_path, deny):
    exercise(tmp_path, deny, True)
