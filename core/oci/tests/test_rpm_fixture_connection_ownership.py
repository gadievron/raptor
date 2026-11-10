"""RPM database fixtures retire SQLite before reading or deleting their file."""

import sqlite3
from contextlib import closing
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

from core.oci.tests import test_sbom as native


def _exercise(tmp_path, phase, error=None, after=True, deny=False):
    records = []
    events = []
    failure = error("owned RPM fixture SQL fault") if error else None

    def assert_closed():
        for connection, _ in records:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                sqlite3.Connection.execute(connection, "SELECT 1")

    class FixturePath(type(Path())):
        def read_bytes(self):
            assert_closed()
            events.append("read")
            return super().read_bytes()

        def unlink(self, *args, **kwargs):
            assert_closed()
            events.append("unlink")
            return super().unlink(*args, **kwargs)

    class Connection(sqlite3.Connection):
        def execute(self, sql, *args):
            selected = error and sql.startswith("CREATE" if phase == "create" else "INSERT")
            if selected and not after:
                raise failure
            result = super().execute(sql, *args)
            if selected:
                raise failure
            return result

        def close(self):
            super().close()
            events.append("close")

    def connected(filename):
        connection = sqlite3.connect(filename, factory=Connection)
        records.append((connection, Path(filename)))
        if deny:
            def authorize(action, name, *rest):
                refused = name == "Packages" and action == (
                    sqlite3.SQLITE_CREATE_TABLE if phase == "create" else sqlite3.SQLITE_INSERT
                )
                return sqlite3.SQLITE_DENY if refused else sqlite3.SQLITE_OK
            connection.set_authorizer(authorize)
        return connection

    body = FunctionType(native._make_rpmdb_sqlite.__code__, {
        **native._make_rpmdb_sqlite.__globals__,
        "sqlite3": SimpleNamespace(connect=connected), "Path": FixturePath,
    })
    expected = error or (sqlite3.DatabaseError if deny else None)
    data = None
    try:
        if expected:
            with pytest.raises(expected, match="not authorized" if deny else "owned RPM fixture SQL fault") as caught:
                body([("fixture-demo", "1.2", "3")])
            if failure is not None:
                assert caught.value is failure
        else:
            data = body([("fixture-demo", "1.2", "3")])
        assert len(records) == 1
        assert_closed()
        assert not records[0][1].exists()
        assert events.index("close") < events.index("unlink")
        assert ("read" in events) is (not bool(expected))
        if data is not None:
            assert events.index("close") < events.index("read") < events.index("unlink")
            path = tmp_path / "verified.sqlite"
            path.write_bytes(data)
            with closing(sqlite3.connect(path)) as reader:
                assert reader.execute("SELECT hnum,blob FROM Packages").fetchall() == [
                    (0, native._make_rpm_header("fixture-demo", "1.2", "3")),
                ]
    finally:
        for connection, path in records:
            sqlite3.Connection.close(connection)
            path.unlink(missing_ok=True)


@pytest.mark.parametrize("phase", ["create", "insert"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_sql_faults_retire_connection_before_unlink(tmp_path, phase, error, after):
    _exercise(tmp_path, phase, error, after)


@pytest.mark.parametrize("phase", ["create", "insert"])
def test_native_sql_refusal_retires_connection_before_unlink(tmp_path, phase):
    _exercise(tmp_path, phase, deny=True)


def test_native_fixture_bytes_read_after_retirement(tmp_path):
    _exercise(tmp_path, "insert")
