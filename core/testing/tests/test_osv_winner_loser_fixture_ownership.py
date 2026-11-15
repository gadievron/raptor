"""Own each offline refresher during its exact acquisition/setup component."""

import __future__
import ast
from contextlib import closing
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import time
import io
import zipfile
import pytest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
PINS = {
    "_ZipServingHttp": "76d0196ec55c5571b9c37cb3082477bda904dfd7d723fecb1e5daed7e4b73237",
    "_make_zip": "f732af7e35826c8e0b292c07919703f0dad5e262ffffe7deeb37f540c902e9c5",
    "_osv": "3299ea1897f88336e8fb589319b4061876d40576b8511ab8cc949f25014a0b9c",
    "test_ingest_rechecks_freshness_after_taking_the_write_lock": "bb42a88c21bed9230cf1ee1151c5b6300c734af39d136cef344a4d90cdc46812",
    "__init__": "ac3320734fc9ff1b6765979b7e5fbfddf2ecfff1ecaf78b41f3725e00d4aacb7",
    "ensure_fresh": "783fbcd142abb0510168f6172f3e7c4a928b11b4665af0a44dcde4856092e347",
    "close": "8e461a9115af3afa45bb666cbc0ff8abfd4e9b8f1f90f3d77474f287193748ce",
    "_init_db": "1fb90685d68a191dc43f4292bdbfe048609c30d9a16ee4e330bf43fbbf18c11f",
    "_is_fresh": "d730633572c04592b0eb7eb7967c9290e6ebea93dafa94cc6d0ecd6279d09131",
    "_ingest_ecosystem": "902f9115cf8e6b0bc2c9022a40539d1931539bb823a6beaa34f60016ae7a9642",
    "_insert_record": "dd33b58bede38556d85425f08d5b266db89eca495a76096c4ef3ffd2ec334336",
}


class SetupBoundary(Exception):
    """Stop after real schema setup, before integration work."""


def _exercise(tmp_path, role, refusal):
    owner = ROOT / "packages/sca/osv_offline.py"
    text = owner.read_text()
    tree = ast.parse(text)
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
        if isinstance(n, ast.FunctionDef)
        and n.name in {"__init__", "_init_db", "close", "ensure_fresh"}
    ]
    assert len(cls.body) == 4
    for node in cls.body:
        assert (
            hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
            == PINS[node.name]
        )
    constants = [
        n
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(
            isinstance(z, ast.Name)
            and z.id in {"_DEFAULT_TTL", "_BUSY_TIMEOUT_SECONDS"}
            for z in n.targets
        )
    ]
    ns = {
        "sqlite3": sqlite3,
        "io": io,
        "json": json,
        "zipfile": zipfile,
        "closing": closing,
    }
    exec(
        compile(
            ast.Module(body=[*constants, cls], type_ignores=[]),
            str(owner),
            "exec",
            flags=__future__.annotations.compiler_flag,
        ),
        ns,
    )
    component = ns["OsvOfflineDB"]
    source = ROOT / "packages/sca/tests/test_osv_offline.py"
    native_text = source.read_text()
    native_tree = ast.parse(native_text)
    native = next(
        n
        for n in native_tree.body
        if isinstance(n, ast.FunctionDef)
        and n.name == "test_ingest_rechecks_freshness_after_taking_the_write_lock"
    )
    assert (
        hashlib.sha256(ast.get_source_segment(native_text, native).encode()).hexdigest()
        == PINS[native.name]
    )
    helpers = [
        n
        for n in native_tree.body
        if isinstance(n, (ast.FunctionDef, ast.ClassDef))
        and n.name in {"_osv", "_make_zip", "_ZipServingHttp"}
    ]
    for n in helpers:
        assert (
            hashlib.sha256(ast.get_source_segment(native_text, n).encode()).hexdigest()
            == PINS[n.name]
        )
    prefix = [
        n
        for n in native.body
        if isinstance(n, ast.Assign)
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id in {"rec", "http"}
    ]
    assert len(prefix) == 2
    ns["tmp_path"] = tmp_path
    exec(
        compile(
            ast.Module(body=[*helpers, *prefix], type_ignores=[]),
            str(source),
            "exec",
            flags=__future__.annotations.compiler_flag,
        ),
        ns,
    )
    database = tmp_path / "osv.sqlite"
    peer = None
    opened, objects, denied = [], [], []
    expected = ("GHSA-race", "PyPI", "racepkg", json.dumps(ns["rec"]))
    stamp = int(time.time())
    try:
        if role == "loser":
            peer = component(database, ttl_seconds=3600)
            peer._init_db()
            peer._conn.execute(
                "INSERT INTO advisories(osv_id,ecosystem,package,json) VALUES (?,?,?,?)",
                expected,
            )
            peer._conn.execute(
                "INSERT INTO ingest_meta(ecosystem,ingested_at) VALUES (?,?)",
                ("PyPI", stamp),
            )
            peer._conn.commit()
            assert not peer._conn.in_transaction

        class BoundaryConnection(sqlite3.Connection):
            def commit(self):
                super().commit()
                assert not self.in_transaction
                if not refusal:
                    raise SetupBoundary("schema committed before integration")

        def connected(path, **kwargs):
            con = sqlite3.connect(path, factory=BoundaryConnection, **kwargs)
            opened.append(con)

            def authorize(action, arg1, arg2, db_name, trigger):
                if (
                    refusal
                    and action == sqlite3.SQLITE_CREATE_TABLE
                    and arg1 == "advisories"
                ):
                    denied.append((action, arg1, arg2, db_name, trigger))
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            con.set_authorizer(authorize)
            return con

        ns["sqlite3"] = SimpleNamespace(connect=connected)

        def acquire(*args, **kwargs):
            obj = component(*args, **kwargs)
            objects.append(obj)
            return obj

        ns["OsvOfflineDB"] = acquire
        outer = next(
            n
            for n in native.body
            if isinstance(n, ast.With) and n.items[0].optional_vars.id == "winner"
        )
        selected = (
            outer
            if role == "winner"
            else next(
                n
                for n in outer.body
                if isinstance(n, ast.With) and n.items[0].optional_vars.id == "loser"
            )
        )
        expected_error = sqlite3.DatabaseError if refusal else SetupBoundary
        with pytest.raises(expected_error) as caught:
            exec(
                compile(
                    ast.Module(body=[selected], type_ignores=[]),
                    str(source),
                    "exec",
                    flags=__future__.annotations.compiler_flag,
                ),
                ns,
            )
        if refusal:
            assert caught.value.sqlite_errorcode == sqlite3.SQLITE_AUTH
            assert len(denied) == 1
        else:
            assert not denied
        assert len(opened) == len(objects) == 1
        con = opened[0]
        assert objects[0]._conn is None
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            con.execute("SELECT 1")
        assert ns["http"].calls == []
        if peer is not None:
            assert con is not peer._conn and not peer._conn.in_transaction
            assert 0 <= int(time.time()) - stamp < 3600
            assert peer._conn.execute(
                "SELECT osv_id,ecosystem,package,json FROM advisories"
            ).fetchall() == [expected]
            assert peer._conn.execute(
                "SELECT ecosystem,ingested_at FROM ingest_meta"
            ).fetchall() == [("PyPI", stamp)]
        (tmp_path / "ownership.json").write_text(
            json.dumps(
                {
                    "role": role,
                    "refusal": refusal,
                    "closed_before_rescue": True,
                    "denied": denied,
                    "http_calls": ns["http"].calls,
                    "supplied_cache_preserved": peer is not None,
                    "scope": "exact acquisition/setup component only; no ingestion, concurrency or full native execution",
                }
            )
            + "\n"
        )
    finally:
        for obj in objects:
            obj.close()
        if peer is not None:
            peer.close()


@pytest.mark.parametrize("role", ["winner", "loser"])
@pytest.mark.parametrize(
    "refusal", [False, True], ids=["setup-boundary", "sqlite-auth"]
)
def test_refresher_setup_ownership(tmp_path, role, refusal):
    _exercise(tmp_path, role, refusal)
