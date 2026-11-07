"""Job indexes skip terminal history without changing queue decisions or data."""

from contextlib import closing

import pytest

from core.audit.cross_entry.progress import WorkQueue


INDEXES = ('queue_delivery_jobs', 'queue_unfinished_jobs', 'queue_runnable_jobs')


@pytest.fixture
def queue(tmp_path):
    with closing(WorkQueue(tmp_path, 'main')) as value:
        yield value


def seed(queue):
    queue.db.execute("INSERT INTO views(namespace,id,extra_file) VALUES ('main','view','a.c')")
    queue.db.executemany('INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?)', [
        ('main', 'view', f'terminal{i:05}', 'consumer', '', 'not_applicable', 1, '{}')
        for i in range(3000)
    ])
    queue.db.commit()


def insert(queue, jid, status, result='{}', namespace='main', view='view'):
    queue.db.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?)',
                     (namespace, view, jid, 'consumer', '', status, 0, result))


@pytest.mark.parametrize('operation', ['pending', 'delivery', 'completion'])
def test_job_queries_skip_unrelated_terminal_history(queue, operation):
    seed(queue)
    if operation == 'pending':
        insert(queue, 'runnable', 'partial')
    elif operation == 'delivery':
        insert(queue, 'paid', 'prepared', '{"key":"evidence"}')
    else:
        insert(queue, 'blocked', 'blocked')
    queue.db.commit()
    work = []
    queue.db.set_progress_handler(lambda: work.append(1) or 0, 100)
    try:
        if operation == 'pending':
            assert [job['id'] for job in queue.pending('view')] == ['runnable']
        elif operation == 'delivery':
            assert [job['evidence'] for job in queue.undelivered('view')] == ['evidence']
        else:
            queue.complete_view_if_finished('view')
    finally:
        queue.db.set_progress_handler(None, 0)
    # No full scan of the 3,000 terminal rows; avoid timing assertions.
    assert len(work) < 10
    if operation == 'completion':
        assert queue.db.execute("SELECT status FROM views WHERE id='view'").fetchone()[0] == 'blocked'


def snapshot(queue):
    return {table: [tuple(row) for row in queue.db.execute(f'SELECT * FROM {table} ORDER BY rowid')]
            for table in ('views', 'jobs', 'acknowledgements')}


def test_existing_database_upgrade_preserves_paid_rows_and_order(queue, tmp_path):
    seed(queue)
    insert(queue, 'z-first', 'complete', '{"key":"paid-first","payload":[1,2]}')
    insert(queue, 'a-second', 'prepared', '{"key":"paid-second"}')
    insert(queue, 'other', 'complete', '{"key":"other-namespace"}', namespace='other')
    insert(queue, 'null-status', None, 'invalid-json-is-not-eligible')
    insert(queue, None, 'pending')
    insert(queue, None, 'pending')
    queue.db.execute("INSERT INTO acknowledgements VALUES ('main','view','a-second','paid-second')")
    for name in INDEXES:
        queue.db.execute(f'DROP INDEX {name}')
    queue.db.commit()
    before = snapshot(queue)
    pending = queue.pending('view')
    delivered = queue.undelivered()
    summary = queue.summary()
    with closing(WorkQueue(tmp_path, 'main')) as upgraded:
        assert snapshot(upgraded) == before
        assert upgraded.pending('view') == pending
        assert upgraded.undelivered() == delivered
        assert upgraded.summary() == summary
        assert [item['id'] for item in delivered] == ['z-first']
        indexes = {row[0] for row in upgraded.db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert set(INDEXES) <= indexes


def test_status_transitions_update_partial_indexes(queue):
    seed(queue)
    insert(queue, 'job', 'pending')
    queue.db.commit()
    assert [job['id'] for job in queue.pending('view')] == ['job']
    queue.finish('view', 'job', 'complete', {'key': 'paid'})
    assert queue.pending('view') == []
    assert queue._undelivered_count('view') == 1
    queue.acknowledge('view', 'job', 'paid')
    assert queue._undelivered_count('view') == 0
    assert queue.db.execute("SELECT status FROM views WHERE id='view'").fetchone()[0] == 'complete'
    queue.finish('view', 'job', 'partial')
    assert [job['id'] for job in queue.pending('view')] == ['job']
    assert queue._undelivered_count('view') == 0
