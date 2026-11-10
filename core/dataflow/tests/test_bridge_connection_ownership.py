"""Own metadata connections without dispatching candidate synthesis."""
from contextlib import closing
import sqlite3
from types import SimpleNamespace

import pytest

from core.dataflow import cvefix_bridge as bridge
from core.dataflow.tests.test_cvefix_bridge_literal_path import seed


@pytest.fixture
def databases(tmp_path, monkeypatch):
    source, target = tmp_path / 'results?#%.sqlite', tmp_path / 'synth.sqlite'
    seed(source)
    state = SimpleNamespace(source=source, target=target, connections=[], closes=[],
                            role='source', operation=None, cleanup=None, native_error=None)

    def forbidden(*args, **kwargs):
        pytest.fail('metadata control dispatched synthesis or provider setup')

    class Connection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            role = 'source' if self is state.connections[0] else 'target'
            try:
                cursor = super().execute(sql, *args, **kwargs)
            except sqlite3.Error as error:
                state.native_error = error
                raise
            if sql.startswith('SELECT fix_hash') and role == state.role and state.operation is not None:
                raise state.operation
            return cursor

        def close(self):
            super().close()
            role = 'source' if self is state.connections[0] else 'target'
            state.closes.append(role)
            if role == state.role and state.cleanup is not None:
                raise state.cleanup

    def connect(path, **kwargs):
        if not state.connections:
            assert path == source.resolve().as_uri() + '?mode=ro'
            assert kwargs == {'uri': True}
        else:
            assert state.closes == ['source']
            assert path == str(target)
        con = sqlite3.connect(path, factory=Connection, **kwargs)
        state.connections.append(con)
        return con

    monkeypatch.setattr(bridge, 'sqlite3', SimpleNamespace(**{**vars(sqlite3), 'connect': connect}))
    for name in ('synthesize_one', 'default_completer', 'model_completer', '_default_search_path'):
        monkeypatch.setattr(bridge, name, forbidden)
    state.run = lambda: bridge.synthesize_from_results(
        source, synth_db=target, work_dir=tmp_path / 'work', proposer=forbidden,
        tier1b_model=None, search_path=str(tmp_path / 'unused-query-packs'), log=lambda *a: None,
    )
    try:
        yield state
    finally:
        for con in state.connections:
            sqlite3.Connection.close(con)


def assert_retired(state):
    assert len(state.closes) == len(state.connections)
    assert state.closes == (['source'] if state.role == 'source' else ['source', 'target'])
    for con in state.connections:
        with pytest.raises(sqlite3.ProgrammingError, match='closed'):
            con.execute('SELECT 1')


@pytest.mark.parametrize('role', ['source', 'target'])
def test_native_query_error_survives_secondary_close(databases, role):
    state = databases
    state.role = role
    state.cleanup = OSError('after native connection close')
    path = state.source if role == 'source' else state.target
    with closing(sqlite3.connect(path)) as con:
        if role == 'source':
            con.execute('DROP TABLE walk_results')
        else:
            con.execute('CREATE TABLE synth_results (unrelated TEXT)')
        con.commit()
    before = state.source.read_bytes()
    with pytest.raises(sqlite3.OperationalError) as caught:
        state.run()
    assert caught.value is state.native_error
    assert state.source.read_bytes() == before
    if role == 'source':
        assert not state.target.exists()
    assert_retired(state)


@pytest.mark.parametrize('role', ['source', 'target'])
@pytest.mark.parametrize('primary', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('secondary', [OSError, MemoryError])
def test_unhandled_query_failure_keeps_identity(databases, role, primary, secondary):
    state = databases
    state.role = role
    state.operation = primary('query operation failed')
    state.cleanup = secondary('after native connection close')
    with pytest.raises(primary) as caught:
        state.run()
    assert caught.value is state.operation
    assert_retired(state)


@pytest.mark.parametrize('role', ['source', 'target'])
@pytest.mark.parametrize('cleanup', [None, OSError, KeyboardInterrupt, SystemExit])
def test_empty_metadata_pass_and_fresh_close_errors(databases, role, cleanup):
    state = databases
    state.role = role
    state.cleanup = cleanup('fresh close failure') if cleanup else None
    if cleanup:
        with pytest.raises(cleanup) as caught:
            state.run()
        assert caught.value is state.cleanup
    else:
        report = state.run()
        assert report.total == report.sound == report.not_sound == report.no_barrier == 0
        assert len(state.connections) == 2
        state.role = 'target'
    assert_retired(state)
