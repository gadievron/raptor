"""Counting paid results preserves delivery and completion semantics."""

import json
from contextlib import closing

import pytest

from core.audit.cross_entry.progress import WorkQueue, pending_report_keys
from core.json import save_json


@pytest.fixture
def queue(tmp_path):
    with closing(WorkQueue(tmp_path, 'main')) as value:
        value.add_views(['report.c', 'other.c'])
        yield value


def view(queue, path='report.c'):
    return queue.db.execute('SELECT id FROM views WHERE namespace=? AND extra_file=?',
                            (queue.namespace, path)).fetchone()[0]


def job(queue, number, status, result, path='report.c'):
    vid = view(queue, path)
    consumer = f'consumer{number}'
    queue.add_jobs(vid, [(consumer, '')])
    jid = queue.db.execute('SELECT id FROM jobs WHERE namespace=? AND view_id=? AND consumer=?',
                           (queue.namespace, vid, consumer)).fetchone()[0]
    queue.finish(vid, jid, status, result)
    return jid


@pytest.mark.parametrize('statuses,has_evidence,expected', [
    pytest.param([], False, 'complete', id='no-jobs'),
    pytest.param(['complete'], False, 'complete', id='keyless-complete'),
    pytest.param(['prepared'], False, 'complete', id='keyless-prepared'),
    pytest.param(['not_applicable', 'obsolete'], False, 'complete', id='terminal'),
    pytest.param(['blocked'], False, 'blocked', id='blocked'),
    pytest.param(['pending'], False, 'pending', id='runnable'),
    pytest.param(['partial'], False, 'pending', id='partial'),
    pytest.param(['retrying'], False, 'pending', id='other-runnable-status'),
    pytest.param(['blocked', 'partial'], False, 'pending', id='blocked-and-runnable'),
    pytest.param(['blocked', 'complete'], True, 'pending', id='paid-result-before-blocked'),
    pytest.param(['prepared'], True, 'pending', id='prepared-evidence'),
])
def test_completion_statuses(queue, statuses, has_evidence, expected):
    for number, status in enumerate(statuses):
        result = {'key': f'evidence{number}'} if has_evidence else {}
        job(queue, number, status, result)
    before = [tuple(r) for r in queue.db.execute('SELECT * FROM jobs ORDER BY rowid')]
    queue.complete_view_if_finished(view(queue))
    status = queue.db.execute('SELECT status FROM views WHERE namespace=? AND id=?',
                              (queue.namespace, view(queue))).fetchone()[0]
    assert status == expected
    assert [tuple(r) for r in queue.db.execute('SELECT * FROM jobs ORDER BY rowid')] == before


def test_counts_and_delivery_preserve_payloads_order_and_filters(queue, tmp_path):
    first = job(queue, 9, 'complete', {'key': 'first', 'nested': {'payload': [1, 2]}})
    second = job(queue, 1, 'prepared', {'key': 'second', 'payload': 'text'})
    acknowledged = job(queue, 3, 'complete', {'key': 'acked'})
    job(queue, 4, 'complete', {})
    job(queue, 5, 'partial', {'key': 'not-ready'})
    job(queue, 6, 'complete', {'key': 'other-view'}, path='other.c')
    queue.acknowledge(view(queue), acknowledged, 'acked')
    with closing(WorkQueue(tmp_path, 'unrelated')) as other:
        other.add_views(['report.c'])
        job(other, 0, 'complete', {'key': 'other-namespace'})
        delivered = queue.undelivered(view(queue))
        assert [entry['id'] for entry in delivered] == [first, second]
        assert delivered[0]['outcome'] == {'key': 'first', 'nested': {'payload': [1, 2]}}
        assert delivered[1]['outcome'] == {'key': 'second', 'payload': 'text'}
        assert [entry['evidence'] for entry in delivered] == ['first', 'second']
        assert queue._undelivered_count(view(queue)) == 2
        assert queue._undelivered_count() == queue.summary()['undelivered_results'] == 3
        assert other.summary()['undelivered_results'] == 1
    queue.acknowledge(view(queue), first, 'first')
    assert queue._undelivered_count(view(queue)) == 1
    assert [entry['id'] for entry in queue.undelivered(view(queue))] == [second]


@pytest.mark.parametrize('operation', ['summary', 'complete', 'delivery', 'reports'])
def test_later_malformed_result_still_refuses_and_closes_cursor(queue, operation, tmp_path):
    job(queue, 0, 'complete', {'key': 'valid-first'})
    malformed = job(queue, 1, 'complete', {})
    job(queue, 2, 'complete', {'key': 'valid-last'})
    queue.db.execute('UPDATE jobs SET result=? WHERE id=?', ('{', malformed))
    queue.db.commit()
    before = [tuple(r) for r in queue.db.execute('SELECT * FROM views ORDER BY id')]
    with pytest.raises(json.JSONDecodeError):
        if operation == 'summary':
            queue.summary()
        elif operation == 'complete':
            queue.complete_view_if_finished(view(queue))
        elif operation == 'reports':
            save_json(tmp_path / 'cross-entry-progress.json', {
                'namespace': 'main', 'report_keys': ['report.c:f'],
            })
            pending_report_keys(tmp_path)
        else:
            queue.undelivered(view(queue))
    assert [tuple(r) for r in queue.db.execute('SELECT * FROM views ORDER BY id')] == before
    # An unfinished read cursor must not keep the owned table locked.
    queue.db.execute('DROP TABLE jobs')


def test_view_scoped_count_does_not_parse_other_views(queue):
    job(queue, 0, 'complete', {'key': 'valid'})
    malformed = job(queue, 1, 'complete', {}, path='other.c')
    queue.db.execute('UPDATE jobs SET result=? WHERE id=?', ('not-json', malformed))
    queue.db.commit()
    assert queue._undelivered_count(view(queue)) == 1
    assert len(queue.undelivered(view(queue))) == 1
    with pytest.raises(json.JSONDecodeError):
        queue.summary()


def test_pending_report_keys_keep_scope_and_acknowledgement_filters(queue, tmp_path):
    save_json(tmp_path / 'cross-entry-progress.json', {
        'namespace': 'main', 'report_keys': ['report.c:f', None, 42],
        'selection_key': 'selection', 'target': str(tmp_path.resolve()),
    })
    assert pending_report_keys(tmp_path) == set()
    jid = job(queue, 0, 'complete', {'key': 'evidence'})
    assert pending_report_keys(tmp_path, selection_key='selection', target=tmp_path) == {'report.c:f'}
    assert pending_report_keys(tmp_path, selection_key='different') == set()
    assert pending_report_keys(tmp_path, target=tmp_path / 'other') == set()
    queue.acknowledge(view(queue), jid, 'evidence')
    assert pending_report_keys(tmp_path) == set()
