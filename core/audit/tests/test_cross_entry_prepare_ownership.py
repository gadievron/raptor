"""Prepare owns its SQLite handles through operation and cleanup failures."""
import sqlite3
from types import SimpleNamespace

import pytest

from core.audit.cross_entry import runner
from core.audit.cross_entry.progress import exclusive_session


@pytest.fixture
def handles(tmp_path, monkeypatch):
    root, out = tmp_path / 'source', tmp_path / 'output'
    root.mkdir()
    state = SimpleNamespace(root=root, out=out, opened={}, closed=[], errors={},
                            primary=None, native_failure=False, native_error=None)
    original_catalogue, original_queue = runner.Catalogue, runner.WorkQueue

    class Catalogue(original_catalogue):
        def __init__(self, *args):
            super().__init__(*args)
            state.opened['catalogue'] = self

        def close(self):
            super().close()
            state.closed.append('catalogue')
            if 'catalogue' in state.errors:
                raise state.errors['catalogue']

    class Queue(original_queue):
        def __init__(self, *args):
            super().__init__(*args)
            state.opened['queue'] = self

        def requests(self):
            if state.native_failure:
                self.db.execute('DROP TABLE report_requests')
            try:
                result = super().requests()
            except sqlite3.Error as error:
                state.native_error = error
                raise
            if state.primary is not None:
                raise state.primary
            return result

        def close(self):
            super().close()
            state.closed.append('queue')
            if 'queue' in state.errors:
                raise state.errors['queue']

    def forbidden(*args, **kwargs):
        pytest.fail('empty index cleanup control dispatched parser or study work')

    monkeypatch.setattr(runner, 'Catalogue', Catalogue)
    monkeypatch.setattr(runner, 'WorkQueue', Queue)
    for name in ('collect_sources', 'load_or_build_index', 'run_studies'):
        monkeypatch.setattr(runner, name, forbidden)
    state.run = lambda: runner.prepare(root, [], mode='index', out_dir=out,
                                       include_dirs=(root,), client=None)
    try:
        yield state
    finally:
        for handle in state.opened.values():
            sqlite3.Connection.close(handle.db)


def assert_retired(state):
    assert state.closed == ['queue', 'catalogue']
    for handle in state.opened.values():
        with pytest.raises(sqlite3.ProgrammingError, match='closed'):
            handle.db.execute('SELECT 1')
    # Reacquisition uses a new native connection and proves the lease retired.
    with exclusive_session(state.out / 'cross-entry-lease.sqlite'):
        pass


@pytest.mark.parametrize('failed_close', ['queue', 'catalogue', 'both'])
def test_native_queue_error_survives_secondary_close(handles, failed_close):
    handles.native_failure = True
    for name in (['queue', 'catalogue'] if failed_close == 'both' else [failed_close]):
        handles.errors[name] = OSError('after native close: ' + name)
    with pytest.raises(sqlite3.OperationalError) as caught:
        handles.run()
    assert caught.value is handles.native_error
    assert_retired(handles)


@pytest.mark.parametrize('failed_close', ['queue', 'catalogue', 'both'])
@pytest.mark.parametrize('primary', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_operation_identity_survives_consumed_cleanup(handles, failed_close, primary):
    handles.primary = primary('request operation failed')
    for name in (['queue', 'catalogue'] if failed_close == 'both' else [failed_close]):
        handles.errors[name] = MemoryError('after native close: ' + name)
    with pytest.raises(primary) as caught:
        handles.run()
    assert caught.value is handles.primary
    assert_retired(handles)


@pytest.mark.parametrize('failed_close', ['queue', 'catalogue'])
@pytest.mark.parametrize('error', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_failure_remains_visible(handles, failed_close, error):
    handles.errors[failed_close] = error('fresh close failure')
    with pytest.raises(error) as caught:
        handles.run()
    assert caught.value is handles.errors[failed_close]
    assert_retired(handles)


def test_two_fresh_close_errors_keep_existing_outer_close_precedence(handles):
    handles.errors = {'queue': OSError('queue close'), 'catalogue': LookupError('catalogue close')}
    with pytest.raises(LookupError) as caught:
        handles.run()
    assert caught.value is handles.errors['catalogue']
    assert_retired(handles)


def test_healthy_empty_index_retires_both_connections(handles):
    assert handles.run() == {}
    assert_retired(handles)
