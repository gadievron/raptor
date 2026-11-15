"""Standalone RPM fixture connections close before reading and unlinking."""

import ast
import builtins
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
from types import SimpleNamespace

import pytest

PINS = {
    "_make_rpm_header": "a74e1303aa89fca9771bf0e45c6121dde0262cfe8007649ed56c172b866ccd49",
    "_make_rpmdb_sqlite": "91a627b5db572b88718d4d498705c3861af9bcff66829e601c9db2a9fe23889f",
    "test_parse_rpm_sqlite_no_packages_table_returns_empty": "112ffbf438835fafbfca7cd7d59a78c51ccfcc9eec2cfcf9851ae7cdb7f3050e",
    "test_parse_rpm_sqlite_invalid_blob_skipped": "a5c86759b27540c9fbede5a31cccbbd7cab6d7fb2b27a6b38fbf02f55cc32680",
}
CASES = [
    "test_parse_rpm_sqlite_no_packages_table_returns_empty",
    "test_parse_rpm_sqlite_invalid_blob_skipped",
]


class ParserBoundary(Exception):
    pass


def exercise(case, deny, tmp_path, expected_closed):
    source = Path(__file__).resolve().parents[3] / "core/oci/tests/test_sbom.py"
    text = source.read_text()
    nodes = {
        n.name: n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef) and n.name in PINS
    }
    assert set(nodes) == set(PINS)
    assert all(
        hashlib.sha256(ast.get_source_segment(text, n).encode()).hexdigest()
        == PINS[name]
        for name, n in nodes.items()
    )
    assert all(not n.decorator_list for n in nodes.values())
    import tempfile

    fixture_paths, connections, denials, unlinks, parser_bytes = [], [], [], [], []

    def named(*args, **kwargs):
        assert "dir" not in kwargs
        handle = tempfile.NamedTemporaryFile(*args, dir=tmp_path, **kwargs)
        fixture_paths.append(Path(handle.name))
        return handle

    importing = builtins.__import__

    def private_import(name, *args, **kwargs):
        if name == "tempfile":
            return SimpleNamespace(NamedTemporaryFile=named)
        return importing(name, *args, **kwargs)

    builtin_view = dict(vars(builtins), __import__=private_import)
    seed_namespace = {
        "__builtins__": builtin_view,
        "Path": Path,
        "closing": closing,
        "struct": struct,
        "sqlite3": sqlite3,
    }
    exec(
        compile(
            ast.Module(
                body=[nodes["_make_rpm_header"], nodes["_make_rpmdb_sqlite"]],
                type_ignores=[],
            ),
            str(source),
            "exec",
        ),
        seed_namespace,
    )

    def is_closed():
        assert len(connections) == 1
        try:
            connections[0].execute("SELECT 1")
        except sqlite3.ProgrammingError as exc:
            assert "closed" in str(exc)
            return True
        return False

    class ObservedPath(type(Path())):
        def unlink(self, *args, **kwargs):
            unlinks.append({"closed": is_closed(), "path": str(self)})
            return super().unlink(*args, **kwargs)

    action = sqlite3.SQLITE_CREATE_TABLE if case == CASES[0] else sqlite3.SQLITE_INSERT
    table = "Other" if case == CASES[0] else "Packages"

    def authorize(operation, name, *rest):
        if operation == action and name == table:
            denials.append((operation, name))
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def connect(path):
        assert Path(path) in fixture_paths
        con = sqlite3.connect(path)
        connections.append(con)
        if deny:
            con.set_authorizer(authorize)
        return con

    def before_parser(data):
        assert is_closed()
        parser_bytes.append(data)
        raise ParserBoundary()

    namespace = {
        "__builtins__": builtin_view,
        "Path": ObservedPath,
        "sqlite3": SimpleNamespace(connect=connect),
        "_make_rpmdb_sqlite": seed_namespace["_make_rpmdb_sqlite"],
        "parse_rpm_sqlite": before_parser,
    }
    exec(
        compile(ast.Module(body=[nodes[case]], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    failed, stopped = False, False
    try:
        try:
            namespace[case]()
        except sqlite3.DatabaseError as exc:
            assert exc.sqlite_errorcode == sqlite3.SQLITE_AUTH
            failed = True
        except ParserBoundary:
            stopped = True
        assert failed is deny and stopped is (not deny)
        assert bool(denials) is deny
        assert len(connections) == len(unlinks) == 1
        state = is_closed()
        record = {
            "case": case,
            "denied": failed,
            "closed_after_call": state,
            "closed_at_unlink": unlinks[0]["closed"],
            "all_fixture_paths_removed": all(
                not path.exists() for path in fixture_paths
            ),
            "parser_calls": len(parser_bytes),
        }
        (tmp_path / "observation.json").write_text(json.dumps(record, indent=2) + "\n")
        assert state is expected_closed and unlinks[0]["closed"] is expected_closed
        assert record["all_fixture_paths_removed"]
        if not deny:
            assert len(parser_bytes) == 1
            verification = tmp_path / "verified.sqlite"
            verification.write_bytes(parser_bytes[0])
            with closing(sqlite3.connect(verification)) as verify:
                if case == CASES[0]:
                    assert verify.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall() == [("Other",)]
                    assert verify.execute("SELECT * FROM Other").fetchall() == []
                else:
                    assert verify.execute(
                        "SELECT hnum,blob FROM Packages ORDER BY hnum"
                    ).fetchall() == [
                        (0, seed_namespace["_make_rpm_header"]("good", "1.0", "1.el9")),
                        (99, b"not a valid rpm header"),
                    ]
    finally:
        for con in connections:
            con.close()
        for path in fixture_paths:
            path.unlink(missing_ok=True)


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("deny", [False, True], ids=["normal-setup", "sql-refusal"])
def test_standalone_rpm_setup_closes_before_unlink(case, deny, tmp_path):
    exercise(case, deny, tmp_path, True)
