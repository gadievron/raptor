"""Scheduling avoids completed rows and reuses changed-file iterables safely."""

from contextlib import closing

import pytest

from core.audit.cross_entry.catalogue import Catalogue, VERSION
from core.audit.cross_entry.progress import WorkQueue


@pytest.fixture
def cat(tmp_path):
    root = tmp_path / 'src'
    out = tmp_path / 'out'
    root.mkdir()
    out.mkdir()
    with closing(Catalogue(root, out)) as value:
        yield value


@pytest.mark.parametrize('kind', ['files', 'directories'])
def test_pending_selection_skips_completed_rows_and_keeps_order(cat, kind):
    cat.db.executemany('INSERT INTO files VALUES (?,?,?,?,?,?,?,?)', [
        (f'done{i:05}.c', 1, 'signature', 'sha', b'', 'indexed', '', VERSION)
        for i in range(3000)
    ] + [
        ('zz-b.c', 1, 'signature', None, None, 'pending', '', VERSION),
        ('zz-a.c', 1, 'signature', None, None, 'pending', '', VERSION),
        ('aa-blocked.c', 1, 'signature', None, None, 'blocked', 'unreadable', VERSION),
    ])
    cat.db.executemany('INSERT INTO directories VALUES (?,?,?)', [
        (f'done{i:05}', 'done', 100) for i in range(3000)
    ] + [('z-high', 'pending', 10), ('a-low', 'pending', 0), ('a-high', 'pending', 10)])
    if kind == 'files':
        query = "SELECT path FROM files WHERE status='pending' ORDER BY path LIMIT 1"
        expected = ['zz-a.c', 'zz-b.c']
        final_status = 'indexed'
    else:
        query = "SELECT path FROM directories WHERE status='pending' ORDER BY priority DESC,path LIMIT 1"
        expected = ['a-high', 'z-high', 'a-low']
        final_status = 'done'
    for path in expected:
        work = []
        cat.db.set_progress_handler(lambda: work.append(1) or 0, 100)
        try:
            row = cat.db.execute(query).fetchone()
        finally:
            cat.db.set_progress_handler(None, 0)
        assert row['path'] == path
        # Fewer than 1,000 VM operations: no scan of the 3,000 completed rows.
        assert len(work) < 10
        cat.db.execute(f'UPDATE {kind} SET status=? WHERE path=?', (final_status, path))
    assert cat.db.execute(query).fetchone() is None


def test_existing_catalogue_acquires_indexes_without_changing_data(tmp_path):
    root = tmp_path / 'src'
    out = tmp_path / 'out'
    root.mkdir()
    out.mkdir()
    with closing(Catalogue(root, out)) as value:
        value.db.execute('DROP INDEX catalogue_pending_files')
        value.db.execute('DROP INDEX catalogue_pending_directories')
        value.db.execute("INSERT INTO directories VALUES ('src','pending',10)")
        value.db.execute('INSERT INTO files VALUES (?,?,?,?,?,?,?,?)',
                         ('src/a.c', 7, 'signature', 'sha', b'body', 'indexed', '', VERSION))
        value.db.commit()
        before = [tuple(r) for r in value.db.execute('SELECT * FROM files')]
    with closing(Catalogue(root, out)) as value:
        assert [tuple(r) for r in value.db.execute('SELECT * FROM files')] == before
        assert [tuple(r) for r in value.db.execute('SELECT * FROM directories')] == [('src', 'pending', 10)]
        indexes = {r[0] for r in value.db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {'catalogue_pending_files', 'catalogue_pending_directories'} <= indexes


@pytest.fixture
def queue(tmp_path):
    with closing(WorkQueue(tmp_path, 'main')) as value:
        yield value


def seed_views(queue, count=4):
    queue.add_views([f'view{i}.c' for i in range(count)])
    for row in queue.db.execute('SELECT id FROM views WHERE namespace=?', (queue.namespace,)).fetchall():
        queue.bind_view(row['id'], 'bound', {'shared.h': 'hash'})
    queue.db.execute("UPDATE views SET status='complete' WHERE namespace=?", (queue.namespace,))
    queue.db.commit()


def view_states(queue):
    return [tuple(r) for r in queue.db.execute(
        'SELECT status,fingerprint FROM views WHERE namespace=? ORDER BY id', (queue.namespace,),
    )]


def test_generator_invalidates_every_dependent_view(queue):
    seed_views(queue)
    queue.invalidate_files(path for path in ['shared.h'])
    assert view_states(queue) == [('pending', '')] * 4


@pytest.mark.parametrize('changed', [[], ['shared.h']], ids=['empty', 'matching'])
def test_changed_iterable_is_materialized_once(queue, changed):
    seed_views(queue)
    iterations = []

    class Changes:
        def __iter__(self):
            iterations.append(1)
            yield from changed

    queue.invalidate_files(Changes())
    assert iterations == [1]
    expected = ('pending', '') if changed else ('complete', 'bound')
    assert view_states(queue) == [expected] * 4


def test_empty_queue_does_not_consume_changed_iterable(queue):
    def changes():
        pytest.fail('an empty queue consumed the changed-file iterable')
        yield 'shared.h'

    queue.invalidate_files(changes())
    assert view_states(queue) == []


def test_invalidation_preserves_unaffected_views_namespaces_and_jobs(queue, tmp_path):
    seed_views(queue, 2)
    rows = queue.db.execute('SELECT id FROM views WHERE namespace=? ORDER BY id', ('main',)).fetchall()
    queue.bind_view(rows[1]['id'], 'other-bound', {'unrelated.h': 'hash'})
    queue.db.execute("UPDATE views SET status='complete' WHERE namespace='main'")
    queue.db.commit()
    queue.add_jobs(rows[0]['id'], [('consumer', '')])
    job = queue.pending(rows[0]['id'])[0]
    queue.finish(rows[0]['id'], job['id'], 'complete', {'key': 'evidence'})
    jobs = [tuple(r) for r in queue.db.execute('SELECT * FROM jobs')]
    with closing(WorkQueue(tmp_path, 'other')) as other:
        seed_views(other, 1)
        queue.invalidate_files(['shared.h'])
        assert view_states(other) == [('complete', 'bound')]
    assert view_states(queue) == [('pending', ''), ('complete', 'other-bound')]
    assert [tuple(r) for r in queue.db.execute('SELECT * FROM jobs')] == jobs
