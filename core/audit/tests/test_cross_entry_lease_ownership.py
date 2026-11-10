"""Cross-entry leases retire native connections even when rollback refuses."""

import sqlite3
from contextlib import closing
from types import SimpleNamespace

import pytest

from core.audit.cross_entry import progress


@pytest.fixture
def lease_connections(monkeypatch):
    opened = []

    class Connection(sqlite3.Connection):
        close_calls = 0
        close_error = None

        def close(self):
            self.close_calls += 1
            super().close()
            if self.close_error is not None:
                raise self.close_error

    def connect(path, **kwargs):
        connection = sqlite3.connect(path, factory=Connection, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(progress, 'sqlite3', SimpleNamespace(connect=connect, OperationalError=sqlite3.OperationalError))
    try:
        yield opened
    finally:
        for connection in opened:
            sqlite3.Connection.close(connection)


def deny_rollback(connection):
    def authorise(operation, value, *args):
        if operation == sqlite3.SQLITE_TRANSACTION and value == 'ROLLBACK':
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    connection.set_authorizer(authorise)


def assert_closed_and_released(connection, path):
    assert connection.close_calls == 1
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        connection.execute('SELECT 1')
    with closing(sqlite3.connect(path, timeout=0, isolation_level=None)) as next_owner:
        next_owner.execute('BEGIN IMMEDIATE')
        next_owner.rollback()


def test_native_rollback_refusal_still_closes_lease(tmp_path, lease_connections):
    path = tmp_path / 'lease.sqlite'
    with pytest.raises(sqlite3.DatabaseError, match='not authorized'):
        with progress.exclusive_session(path):
            assert lease_connections[0].in_transaction
            deny_rollback(lease_connections[0])
    assert_closed_and_released(lease_connections[0], path)


@pytest.mark.parametrize('error_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_body_error_survives_rollback_and_consumed_close_errors(tmp_path, lease_connections, error_type):
    path = tmp_path / 'lease.sqlite'
    primary = error_type('body failure')
    with pytest.raises(error_type) as raised:
        with progress.exclusive_session(path):
            deny_rollback(lease_connections[0])
            lease_connections[0].close_error = OSError('consumed close failure')
            raise primary
    assert raised.value is primary
    assert_closed_and_released(lease_connections[0], path)


def test_fresh_consumed_close_error_is_visible(tmp_path, lease_connections):
    path = tmp_path / 'lease.sqlite'
    failure = OSError('consumed close failure')
    with pytest.raises(OSError) as raised:
        with progress.exclusive_session(path):
            lease_connections[0].close_error = failure
    assert raised.value is failure
    assert_closed_and_released(lease_connections[0], path)


def test_successful_lease_releases_native_transaction(tmp_path, lease_connections):
    path = tmp_path / 'lease.sqlite'
    with progress.exclusive_session(path):
        assert lease_connections[0].in_transaction
        with closing(sqlite3.connect(path, timeout=0, isolation_level=None)) as contender:
            with pytest.raises(sqlite3.OperationalError, match='locked'):
                contender.execute('BEGIN IMMEDIATE')
    assert_closed_and_released(lease_connections[0], path)
