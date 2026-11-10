"""The native graph connection belongs to its constructor until return."""
import sqlite3

import pytest

from core.testing.module_bindings import patch_module_attribute
from core.understand_graph import store


def test_newer_schema_refusal_closes_native_connection(tmp_path, monkeypatch):
    path = tmp_path / "graph.sqlite"
    seed = sqlite3.connect(path)
    try:
        seed.execute("PRAGMA journal_mode=WAL")
        seed.execute("CREATE TABLE retained(value TEXT)")
        seed.execute("INSERT INTO retained VALUES ('previous data')")
        seed.execute(f"PRAGMA user_version={store.SCHEMA_VERSION + 1}")
        seed.commit()
    finally:
        seed.close()
    native_connect = sqlite3.connect
    opened = []

    def connect(*args, **kwargs):
        conn = native_connect(*args, **kwargs)
        opened.append(conn)
        return conn

    patch_module_attribute(monkeypatch, store, "sqlite3", "connect", connect)
    try:
        with pytest.raises(store.GraphSchemaNewerError):
            store.open_graph(path)
        assert len(opened) == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            opened[0].execute("SELECT 1")
        assert path.is_file() and not list(tmp_path.glob("*.corrupt-*"))
        check = native_connect(path)
        try:
            assert check.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION + 1
            assert check.execute("SELECT value FROM retained").fetchone()[0] == "previous data"
        finally:
            check.close()
    finally:
        for conn in opened:
            conn.close()


def _setup_failure(tmp_path, monkeypatch, phase, failure_type, cleanup_type=None):
    path = tmp_path / "graph.sqlite"
    primary = failure_type("graph setup failed")
    native_connect = sqlite3.connect
    native_verify, native_migrate = store._verify_connected_identity, store.migrate
    opened, closed, reached = [], [], []

    class Connection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql.startswith("PRAGMA " + phase):
                reached.append(phase)
                raise primary
            return super().execute(sql, *args, **kwargs)

        def close(self):
            closed.append(self)
            super().close()
            if cleanup_type is not None:
                raise cleanup_type("connection cleanup failed")

    def connect(*args, **kwargs):
        conn = native_connect(*args, factory=Connection, **kwargs)
        opened.append(conn)
        return conn

    def verify(*args):
        native_verify(*args)
        if phase == "identity":
            reached.append(phase)
            raise primary

    def migrate(conn):
        if phase == "migration":
            reached.append(phase)
            raise primary
        native_migrate(conn)

    patch_module_attribute(monkeypatch, store, "sqlite3", "connect", connect)
    monkeypatch.setattr(store, "_verify_connected_identity", verify)
    monkeypatch.setattr(store, "migrate", migrate)
    try:
        with pytest.raises(failure_type) as caught:
            store.open_graph(path)
        assert caught.value is primary and reached == [phase]
        assert len(opened) == 1 and closed == opened
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            opened[0].execute("SELECT 1")
        assert path.is_file() and not list(tmp_path.glob("*.corrupt-*"))
    finally:
        for conn in opened:
            sqlite3.Connection.close(conn)


@pytest.mark.parametrize("phase", ["identity", "busy_timeout", "foreign_keys", "journal_mode", "synchronous", "migration"])
@pytest.mark.parametrize("failure_type", [sqlite3.OperationalError, KeyboardInterrupt, SystemExit])
def test_setup_failure_retires_native_connection(tmp_path, monkeypatch, phase, failure_type):
    _setup_failure(tmp_path, monkeypatch, phase, failure_type)


@pytest.mark.parametrize("cleanup_type", [sqlite3.OperationalError, KeyboardInterrupt, SystemExit])
def test_connection_cleanup_retains_primary_setup_error(tmp_path, monkeypatch, cleanup_type):
    _setup_failure(tmp_path, monkeypatch, "foreign_keys", sqlite3.OperationalError, cleanup_type)
