"""Queue indexes preserve view metadata, scheduling turns and tie behaviour."""

from contextlib import closing

import pytest

from core.audit.cross_entry.progress import WorkQueue


@pytest.fixture
def queue(tmp_path):
    with closing(WorkQueue(tmp_path, 'main')) as value:
        yield value


def rows(queue, table):
    return [tuple(r) for r in queue.db.execute(f'SELECT * FROM {table} ORDER BY 1,2,3')]


def test_reviving_obsolete_views_preserves_paid_jobs_and_other_metadata(queue, tmp_path):
    queue.add_views(['a.c', 'b.c', 'c.c'])
    queue.db.execute("UPDATE views SET fingerprint='bound',last_turn=17,dependencies='{}'")
    queue.db.execute("UPDATE views SET status='obsolete' WHERE extra_file='a.c'")
    queue.db.execute("UPDATE views SET status='complete' WHERE extra_file='b.c'")
    queue.db.commit()
    vid = queue.db.execute("SELECT id FROM views WHERE extra_file='a.c'").fetchone()[0]
    queue.add_jobs(vid, [('consumer', '')])
    jid = queue.pending(vid)[0]['id']
    queue.finish(vid, jid, 'complete', {'key': 'evidence', 'payload': {'paid': True}})
    before_jobs = rows(queue, 'jobs')
    with closing(WorkQueue(tmp_path, 'other')) as other:
        other.add_views(['a.c'])
        other.db.execute("UPDATE views SET status='obsolete',fingerprint='other' WHERE namespace='other'")
        other.db.commit()
        queue.add_views(path for path in ['a.c', 'b.c', 'a.c', 'new.c'])
        states = {r['extra_file']: dict(r) for r in queue.db.execute('SELECT * FROM views WHERE namespace=?', ('main',))}
        assert states['a.c']['status'] == 'pending'
        assert states['a.c']['fingerprint'] == ''
        assert states['a.c']['last_turn'] == 17
        assert states['a.c']['dependencies'] == '{}'
        assert states['b.c']['status'] == 'complete'
        assert states['b.c']['fingerprint'] == 'bound'
        assert states['c.c']['fingerprint'] == 'bound'
        assert states['new.c']['status'] == 'pending'
        assert states['new.c']['last_turn'] == 0
        assert tuple(other.db.execute('SELECT status,fingerprint FROM views WHERE namespace=?', ('other',)).fetchone()) == ('obsolete', 'other')
    assert rows(queue, 'jobs') == before_jobs


@pytest.mark.parametrize('turns,expected', [
    pytest.param([None, None], 1, id='all-null'),
    pytest.param([-5, -2], -1, id='negative'),
    pytest.param([0, 0], 1, id='zero'),
    pytest.param([None, 7], 8, id='mixed-null'),
    pytest.param([None, -3], -2, id='null-is-not-zero'),
    pytest.param([None, 2**63 - 2], 2**63 - 1, id='large-integer'),
])
def test_turn_counter_retains_max_and_null_semantics(queue, turns, expected):
    queue.add_views(['a.c', 'b.c'])
    for path, turn in zip(['a.c', 'b.c'], turns):
        queue.db.execute('UPDATE views SET last_turn=? WHERE extra_file=?', (turn, path))
    queue.db.commit()
    selected = queue.next_view()
    assert selected['extra_file'] == 'a.c'
    assert selected['last_turn'] == turns[0]  # Existing API returns the pre-update row.
    assert queue.db.execute('SELECT last_turn FROM views WHERE id=?', (selected['id'],)).fetchone()[0] == expected


def test_counter_includes_finished_views_and_excludes_other_namespaces(queue, tmp_path):
    queue.add_views(['pending.c', 'finished.c'])
    queue.db.execute("UPDATE views SET status='complete',last_turn=100 WHERE extra_file='finished.c'")
    queue.db.commit()
    with closing(WorkQueue(tmp_path, 'other')) as other:
        other.add_views(['other.c'])
        other.db.execute("UPDATE views SET last_turn=10000 WHERE namespace='other'")
        other.db.commit()
        selected = queue.next_view()
    assert selected['extra_file'] == 'pending.c'
    assert queue.db.execute('SELECT last_turn FROM views WHERE id=?', (selected['id'],)).fetchone()[0] == 101


@pytest.mark.parametrize('operation', ['revive', 'counter'])
def test_indexed_operations_skip_unrelated_views(queue, operation):
    queue.db.executemany('INSERT INTO views VALUES (?,?,?,?,?,?,?)', [
        ('main', f'id{i:05}', f'file{i:05}.c', 'bound', 'complete', i, '{}')
        for i in range(3000)
    ] + [('main', 'obsolete', 'obsolete.c', 'bound', 'obsolete', None, '{}')])
    queue.db.commit()
    work = []
    queue.db.set_progress_handler(lambda: work.append(1) or 0, 100)
    try:
        if operation == 'revive':
            queue.db.execute("UPDATE views SET status='pending',fingerprint='' WHERE namespace=? AND extra_file=? AND status='obsolete'", ('main', 'obsolete.c'))
        else:
            result = queue.db.execute('SELECT coalesce(max(last_turn),0)+1 FROM views WHERE namespace=? AND last_turn IS NOT NULL', ('main',)).fetchone()[0]
            assert result == 3000
    finally:
        queue.db.set_progress_handler(None, 0)
    assert len(work) < 10  # Fewer than 1,000 VM operations, independent of completed rows.
    if operation == 'revive':
        assert tuple(queue.db.execute("SELECT status,fingerprint FROM views WHERE id='obsolete'").fetchone()) == ('pending', '')


def test_existing_database_upgrade_preserves_rows_and_pending_ties(queue, tmp_path):
    queue.db.execute('DROP INDEX queue_obsolete_views')
    queue.db.execute('DROP INDEX queue_nonnull_turns')
    # Legal legacy rows with equal ordering keys must retain their selection.
    queue.db.executemany('INSERT INTO views VALUES (?,?,?,?,?,?,?)', [
        ('main', 'z-first', 'same.c', 'bound', 'pending', 0, '{}'),
        ('main', 'a-second', 'same.c', 'bound', 'pending', 0, '{}'),
    ])
    queue.add_jobs('z-first', [('consumer', '')])
    jid = queue.pending('z-first')[0]['id']
    queue.finish('z-first', jid, 'complete', {'key': 'paid'})
    before = {table: rows(queue, table) for table in ('views', 'jobs', 'acknowledgements')}
    expected = dict(queue.db.execute("SELECT * FROM views WHERE namespace=? AND status='pending' ORDER BY last_turn,extra_file LIMIT 1", ('main',)).fetchone())
    with closing(WorkQueue(tmp_path, 'main')) as upgraded:
        assert {table: rows(upgraded, table) for table in before} == before
        indexes = {r[0] for r in upgraded.db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {'queue_obsolete_views', 'queue_nonnull_turns'} <= indexes
        assert upgraded.next_view() == expected


def test_pending_selection_cannot_use_the_new_partial_indexes(queue):
    plan = queue.db.execute("EXPLAIN QUERY PLAN SELECT * FROM views WHERE namespace=? AND status='pending' ORDER BY last_turn,extra_file LIMIT 1", ('main',))
    details = ' '.join(r[3] for r in plan)
    assert 'queue_obsolete_views' not in details
    assert 'queue_nonnull_turns' not in details
