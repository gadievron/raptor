"""Repeated catalogue and queue bookkeeping leaves unchanged rows unwritten."""

import hashlib
from contextlib import closing

import pytest

from core.audit.cross_entry.catalogue import Catalogue, VERSION
from core.audit.cross_entry.progress import WorkQueue


@pytest.fixture
def cat(tmp_path):
    root = tmp_path / 'src'
    out = tmp_path / 'catalogue'
    root.mkdir()
    out.mkdir()
    with closing(Catalogue(root, out)) as value:
        value.begin()
        source = 'void f(struct item *p){p->value=1;}'
        (root / 'm.c').write_text(source)
        value.ingest({'m.c': source}, {'m.c': hashlib.sha256(source.encode()).hexdigest()})
        value.changed.clear()
        yield value


def file_row(cat):
    return dict(cat.db.execute("SELECT * FROM files WHERE path='m.c'").fetchone())


def test_repeated_discovery_keeps_fresh_stats_without_writes(cat):
    calls = []

    class RootPath(type(cat.root)):
        def stat(self, *args, **kwargs):
            calls.append(self)
            return super().stat(*args, **kwargs)

    cat.root = RootPath(cat.root)
    before = file_row(cat)
    writes = cat.db.total_changes
    cat._discover('m.c')
    assert cat.db.in_transaction
    assert cat.db.total_changes == writes + 1
    for _ in range(3):
        cat._discover('m.c')
    assert calls == [cat.root / 'm.c'] * 4
    assert file_row(cat) == before
    assert cat.db.total_changes == writes + 1
    assert cat.changed_files() == []


def test_new_generation_is_recorded_once(cat):
    cat._set('active', 0)
    cat.db.commit()
    cat.begin()
    writes = cat.db.total_changes
    cat._discover('m.c')
    assert file_row(cat)['seen'] == 2
    assert cat.db.total_changes == writes + 1
    cat._discover('m.c')
    assert cat.db.total_changes == writes + 1
    assert cat.changed_files() == []


@pytest.mark.parametrize('change', ['signature', 'version', 'blocked'])
def test_same_generation_still_requeues_changed_or_blocked_files(cat, change):
    if change == 'signature':
        with (cat.root / 'm.c').open('a') as stream:
            stream.write('\n/* changed */')
    elif change == 'version':
        cat.db.execute("UPDATE files SET version=? WHERE path='m.c'", (VERSION - 1,))
    else:
        cat.db.execute("UPDATE files SET status='blocked',error='unreadable' WHERE path='m.c'")
    cat.db.commit()
    writes = cat.db.total_changes
    cat._discover('m.c')
    result = file_row(cat)
    assert result['status'] == 'pending'
    assert result['error'] == ''
    assert result['seen'] == 1
    assert cat.db.total_changes == writes + 1
    assert cat.changed_files() == ['m.c']


@pytest.mark.parametrize('seen', [None, 'legacy', b'legacy'], ids=['null', 'text', 'blob'])
def test_legacy_seen_values_are_still_normalised(cat, seen):
    cat.db.execute("UPDATE files SET seen=? WHERE path='m.c'", (seen,))
    cat.db.commit()
    writes = cat.db.total_changes
    cat._discover('m.c')
    assert type(file_row(cat)['seen']) is int
    assert file_row(cat)['seen'] == 1
    assert cat.db.total_changes == writes + 1


@pytest.fixture
def queue(tmp_path):
    with closing(WorkQueue(tmp_path, 'main')) as value:
        value.add_views(['gone.c', 'active.c'])
        yield value


def gone_view(queue):
    return queue.db.execute("SELECT id FROM views WHERE namespace='main' AND extra_file='gone.c'").fetchone()[0]


def seed_job(queue, name, status):
    vid = gone_view(queue)
    queue.add_jobs(vid, [(name, '')])
    jid = queue.db.execute('SELECT id FROM jobs WHERE namespace=? AND view_id=? AND consumer=?',
                           ('main', vid, name)).fetchone()[0]
    queue.finish(vid, jid, status, {'key': name, 'payload': {'paid': True}})
    return jid


def paid_rows(queue):
    return [dict(r) for r in queue.db.execute("SELECT * FROM jobs WHERE namespace='main' ORDER BY id")]


def test_repeated_reconciliation_does_not_rewrite_obsolete_rows(queue):
    for number, status in enumerate(['pending', 'partial', 'complete', 'prepared', 'blocked', 'obsolete', None]):
        seed_job(queue, f'consumer{number}', status)
    before = paid_rows(queue)
    queue.reconcile_views(['active.c'])
    expected = [{**row, 'status': 'obsolete'} for row in before]
    assert paid_rows(queue) == expected
    assert queue.db.execute('SELECT status FROM views WHERE id=?', (gone_view(queue),)).fetchone()[0] == 'obsolete'
    writes = queue.db.total_changes
    queue.reconcile_views(['active.c'])
    assert queue.db.total_changes == writes
    assert paid_rows(queue) == expected


def test_new_jobs_on_an_obsolete_view_are_still_obsoleted(queue):
    seed_job(queue, 'first', 'complete')
    queue.reconcile_views(['active.c'])
    late = seed_job(queue, 'late', 'pending')
    before = paid_rows(queue)
    writes = queue.db.total_changes
    queue.reconcile_views(['active.c'])
    assert queue.db.total_changes == writes + 1
    assert paid_rows(queue) == [{**row, 'status': 'obsolete'} for row in before]
    assert queue.db.execute('SELECT status FROM jobs WHERE id=?', (late,)).fetchone()[0] == 'obsolete'


@pytest.mark.parametrize('status', [None, 'complete', 'obsolete'], ids=['null-view', 'finished-view', 'obsolete-view'])
def test_nullable_statuses_preserve_reconciliation_semantics(queue, status):
    seed_job(queue, 'null-job', None)
    queue.db.execute('UPDATE views SET status=? WHERE namespace=? AND id=?', (status, 'main', gone_view(queue)))
    queue.db.commit()
    queue.reconcile_views(['active.c'])
    assert paid_rows(queue)[0]['status'] == 'obsolete'
    assert queue.db.execute('SELECT status FROM views WHERE id=?', (gone_view(queue),)).fetchone()[0] == 'obsolete'


def test_other_namespaces_and_acknowledgements_are_untouched(queue, tmp_path):
    jid = seed_job(queue, 'paid', 'complete')
    queue.acknowledge(gone_view(queue), jid, 'paid')
    before = [tuple(r) for r in queue.db.execute('SELECT * FROM acknowledgements')]
    with closing(WorkQueue(tmp_path, 'other')) as other:
        other.add_views(['gone.c'])
        queue.reconcile_views([])
        assert other.db.execute("SELECT status FROM views WHERE namespace='other'").fetchone()[0] == 'pending'
    assert [tuple(r) for r in queue.db.execute('SELECT * FROM acknowledgements')] == before
