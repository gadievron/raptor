"""Catalogue construction owns native connections until setup completes."""

import sqlite3
from contextlib import closing
from types import SimpleNamespace

import pytest

from core.audit.cross_entry import catalogue


@pytest.fixture
def connections(monkeypatch):
    opened = []

    class Connection(sqlite3.Connection):
        close_calls = 0
        close_error = None

        def close(self):
            self.close_calls += 1
            super().close()
            if self.close_error is not None:
                raise self.close_error

    def connect(path):
        connection = sqlite3.connect(path, factory=Connection)
        opened.append(connection)
        return connection

    monkeypatch.setattr(catalogue, 'sqlite3', SimpleNamespace(connect=connect, Row=sqlite3.Row))
    try:
        yield opened
    finally:
        for connection in opened:
            sqlite3.Connection.close(connection)


def paths(tmp_path):
    root, out = tmp_path / 'source', tmp_path / 'output'
    root.mkdir()
    out.mkdir()
    return root, out


def test_native_schema_failure_closes_unreturned_connection(tmp_path, connections):
    root, out = paths(tmp_path)
    path = out / ('cross-entry-catalogue-' + catalogue.digest(str(root.resolve()))[:16] + '.sqlite')
    with closing(sqlite3.connect(path)) as seed:
        seed.execute('CREATE TABLE terms(term TEXT)')
        seed.commit()
    with pytest.raises(sqlite3.OperationalError, match='no such column: path'):
        catalogue.Catalogue(root, out)
    assert len(connections) == 1
    assert connections[0].close_calls == 1
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        connections[0].execute('SELECT 1')
    with closing(sqlite3.connect(path)) as preserved:
        assert [row[1] for row in preserved.execute('PRAGMA table_info(terms)')] == ['term']


@pytest.mark.parametrize('error_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_setup_error_survives_consumed_close_failure(tmp_path, connections, monkeypatch, error_type):
    root, out = paths(tmp_path)
    primary = error_type('schema setup')
    close_error = OSError('close diagnostic')
    class Connection(sqlite3.Connection):
        close_calls = 0

        def executescript(self, script):
            raise primary

        def close(self):
            self.close_calls += 1
            super().close()
            raise close_error

    def fault_connect(path):
        connection = sqlite3.connect(path, factory=Connection)
        connections.append(connection)
        return connection

    monkeypatch.setattr(catalogue, 'sqlite3', SimpleNamespace(connect=fault_connect, Row=sqlite3.Row))
    with pytest.raises(error_type) as raised:
        catalogue.Catalogue(root, out)
    assert raised.value is primary
    assert connections[0].close_calls == 1
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        connections[0].execute('SELECT 1')


def test_successful_constructor_transfers_live_connection(tmp_path, connections):
    root, out = paths(tmp_path)
    with closing(catalogue.Catalogue(root, out)) as value:
        assert value.db is connections[0]
        assert value.db.close_calls == 0
        value.begin()
        assert value.db.execute("SELECT value FROM meta WHERE key='active'").fetchone()[0] == '1'
        assert value.changed == set()
    assert connections[0].close_calls == 1
