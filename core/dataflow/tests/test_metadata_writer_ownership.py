"""Own synthetic metadata writes without harvesting or resolving refs."""
from contextlib import closing
import sqlite3
from types import SimpleNamespace

import pytest

from core.dataflow import ghsa_harvester as gh
from core.dataflow.cvefix_loader import load_pairs


@pytest.fixture
def writer(tmp_path, monkeypatch):
    path = tmp_path / 'metadata?#%.sqlite'
    item = gh.HarvestedFix('CVE-OWNED', 'CWE-79', 'https://github.com/owned/unused',
                           'Python', 'a' * 40, 'b' * 40)
    state = SimpleNamespace(path=path, item=item, connections=[], closes=0,
                            deny=False, primary=None, phase='schema', cleanup=None, native_error=None)

    class Connection(sqlite3.Connection):
        def executescript(self, sql):
            value = super().executescript(sql)
            if state.phase == 'schema' and state.primary is not None:
                raise state.primary
            return value

        def execute(self, *args, **kwargs):
            try:
                return super().execute(*args, **kwargs)
            except sqlite3.Error as error:
                state.native_error = error
                raise

        def commit(self):
            super().commit()
            if state.phase == 'commit' and state.primary is not None:
                raise state.primary

        def close(self):
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    def connect(db):
        assert db == path
        con = sqlite3.connect(db, factory=Connection)
        state.connections.append(con)
        if state.deny:
            con.set_authorizer(lambda action, name, *rest:
                               sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and name == 'fixes'
                               else sqlite3.SQLITE_OK)
        return con

    def forbidden(*args, **kwargs):
        pytest.fail('metadata writer control dispatched harvesting or git resolution')

    monkeypatch.setattr(gh, 'sqlite3', SimpleNamespace(**{**vars(sqlite3), 'connect': connect}))
    for name in ('_resolve_parent', '_iter_advisories'):
        monkeypatch.setattr(gh, name, forbidden)
    try:
        yield state
    finally:
        for con in state.connections:
            sqlite3.Connection.close(con)


def assert_retired(state):
    assert state.closes == len(state.connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        state.connections[0].execute('SELECT 1')


def test_native_insert_refusal_survives_secondary_close(writer):
    writer.deny = True
    writer.cleanup = OSError('after native connection close')
    with pytest.raises(sqlite3.DatabaseError) as caught:
        gh._write_metadata_db(writer.path, [writer.item])
    assert caught.value is writer.native_error
    assert_retired(writer)


@pytest.mark.parametrize('phase', ['schema', 'commit'])
@pytest.mark.parametrize('primary', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup', [OSError, MemoryError])
def test_write_failure_keeps_primary_identity(writer, phase, primary, cleanup):
    writer.phase = phase
    writer.primary = primary('operation failure')
    writer.cleanup = cleanup('after native connection close')
    with pytest.raises(primary) as caught:
        gh._write_metadata_db(writer.path, [writer.item])
    assert caught.value is writer.primary
    assert_retired(writer)
    if phase == 'commit':
        # An error raised after native commit does not undo committed data.
        assert load_pairs(writer.path)[0].fix_hash == writer.item.fix_hash


@pytest.mark.parametrize('cleanup', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_failure_stays_visible_after_commit(writer, cleanup):
    writer.cleanup = cleanup('fresh close failure')
    with pytest.raises(cleanup) as caught:
        gh._write_metadata_db(writer.path, [writer.item])
    assert caught.value is writer.cleanup
    assert_retired(writer)
    assert load_pairs(writer.path)[0].fix_hash == writer.item.fix_hash


@pytest.mark.parametrize('empty', [False, True])
def test_healthy_writer_remains_loader_compatible(writer, empty):
    writer.path.write_bytes(b'old destination is replaced')
    assert gh._write_metadata_db(writer.path, [] if empty else [writer.item, writer.item]) is None
    assert_retired(writer)
    pairs = load_pairs(writer.path)
    assert len(pairs) == (0 if empty else 1)
    if not empty:
        assert pairs[0].fix_hash == writer.item.fix_hash
        assert pairs[0].parent_hash == writer.item.parent_hash
    with closing(sqlite3.connect(writer.path)) as con:
        assert con.execute('SELECT count(*) FROM fixes').fetchone()[0] == len(pairs)
