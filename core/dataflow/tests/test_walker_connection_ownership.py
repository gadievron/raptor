"""Retire walker metadata connections without dispatching target work."""
from contextlib import closing
import sqlite3
from types import SimpleNamespace

import pytest

from core.dataflow import cvefix_walk as walker
from core.dataflow.ghsa_harvester import _SCHEMA as METADATA_SCHEMA


@pytest.fixture
def database(tmp_path, monkeypatch):
    metadata, results = tmp_path / 'metadata?#%.sqlite', tmp_path / 'results.sqlite'
    with closing(sqlite3.connect(metadata)) as con:
        con.executescript(METADATA_SCHEMA)
    state = SimpleNamespace(metadata=metadata, results=results, connections=[], closes=0,
                            primary=None, cleanup=None, native_error=None)

    class Connection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            try:
                cursor = super().execute(sql, *args, **kwargs)
            except sqlite3.Error as error:
                state.native_error = error
                raise
            if sql.startswith('SELECT fix_hash') and state.primary is not None:
                raise state.primary
            return cursor

        def close(self):
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    def connect(path):
        assert path == str(results)
        con = sqlite3.connect(path, factory=Connection)
        state.connections.append(con)
        return con

    def forbidden(*args, **kwargs):
        pytest.fail('empty metadata control dispatched target or git work')

    monkeypatch.setattr(walker, 'sqlite3', SimpleNamespace(**{**vars(sqlite3), 'connect': connect}))
    for name in ('process_pair', 'safe_git_command', 'safe_git_readonly_command'):
        monkeypatch.setattr(walker, name, forbidden)
    state.run = lambda entry: (
        walker.walk(metadata, results, work_dir=tmp_path / 'work', log=lambda *a: None)
        if entry == 'walk' else
        walker.promote_misses(results, work_dir=tmp_path / 'work', log=lambda *a: None)
    )
    try:
        yield state
    finally:
        for con in state.connections:
            sqlite3.Connection.close(con)


def assert_retired(state):
    assert state.closes == len(state.connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        state.connections[0].execute('SELECT 1')


@pytest.mark.parametrize('entry', ['walk', 'promote'])
def test_native_schema_error_survives_secondary_close(database, entry):
    with closing(sqlite3.connect(database.results)) as con:
        con.execute('CREATE TABLE walk_results (unrelated TEXT)')
    database.cleanup = OSError('after native connection close')
    with pytest.raises(sqlite3.OperationalError) as caught:
        database.run(entry)
    assert caught.value is database.native_error
    assert_retired(database)


@pytest.mark.parametrize('entry', ['walk', 'promote'])
@pytest.mark.parametrize('primary', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_unhandled_operation_keeps_identity(database, entry, primary, cleanup):
    database.primary = primary('operation failed')
    database.cleanup = cleanup('after native connection close')
    with pytest.raises(primary) as caught:
        database.run(entry)
    assert caught.value is database.primary
    assert_retired(database)


@pytest.mark.parametrize('entry', ['walk', 'promote'])
@pytest.mark.parametrize('cleanup', [None, OSError, KeyboardInterrupt, SystemExit])
def test_healthy_empty_pass_and_fresh_close_policy(database, entry, cleanup):
    database.cleanup = cleanup('fresh close failure') if cleanup else None
    if cleanup:
        with pytest.raises(cleanup) as caught:
            database.run(entry)
        assert caught.value is database.cleanup
    else:
        expected = {'total': 0, 'yield': 0, 'fp_candidate': 0} if entry == 'walk' else {'candidates': 0, 'promoted': 0}
        assert database.run(entry) == expected
    assert_retired(database)
