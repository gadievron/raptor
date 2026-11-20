"""Work-DB JSON columns parse through the size gate, never bare json.loads."""

from contextlib import closing

import pytest

import core.audit.cross_entry.progress as progress_module
from core.audit.cross_entry.progress import WorkQueue
from core.json import JsonBudgetExceededError


@pytest.fixture
def queue(tmp_path):
    with closing(WorkQueue(tmp_path, 'main')) as value:
        value.add_views(['report.c'])
        yield value


@pytest.fixture
def small_budget(monkeypatch):
    # The gate reads the module-level binding; a planted multi-gigabyte
    # column is modelled by shrinking the budget under a small payload.
    monkeypatch.setattr(progress_module, 'DEFAULT_JSON_MAX_BYTES', 64)


def view(queue):
    return queue.db.execute('SELECT id FROM views WHERE namespace=?',
                            (queue.namespace,)).fetchone()[0]


def oversized(width=4096):
    return '{"key": "' + 'a' * width + '"}'


def plant_job(queue, status, result):
    vid = view(queue)
    queue.db.execute(
        'INSERT INTO jobs(namespace,view_id,id,consumer,focus,status,result) VALUES (?,?,?,?,?,?,?)',
        (queue.namespace, vid, 'job1', 'consumer1', '', status, result))
    queue.db.commit()


def test_oversized_request_column_refused(queue, small_budget):
    queue.db.execute('INSERT INTO report_requests VALUES (?,?,?)',
                     (queue.namespace, 'k', oversized()))
    queue.db.commit()
    with pytest.raises(JsonBudgetExceededError):
        queue.requests()


def test_oversized_dependencies_column_refused(queue, small_budget):
    queue.db.execute('UPDATE views SET dependencies=? WHERE namespace=?',
                     ('[' + oversized() + ']', queue.namespace))
    queue.db.commit()
    with pytest.raises(JsonBudgetExceededError):
        queue.invalidate_files(['report.c'])


def test_oversized_result_column_refused_in_delivery(queue, small_budget):
    plant_job(queue, 'complete', oversized())
    with pytest.raises(JsonBudgetExceededError):
        queue.undelivered()


def test_oversized_blocked_detail_refused_in_summary(queue, small_budget):
    plant_job(queue, 'blocked', oversized())
    with pytest.raises(JsonBudgetExceededError):
        queue.summary()


def test_budget_error_is_a_value_error(queue, small_budget):
    # Existing malformed-JSON handling (ValueError family) covers the
    # refusal without new plumbing at call sites.
    plant_job(queue, 'complete', oversized())
    with pytest.raises(ValueError):
        queue.undelivered()


def test_normal_columns_round_trip(queue):
    queue.add_requests([{'file': 'report.c', 'name': 'f', 'line_start': 1}])
    assert queue.requests() == [{'file': 'report.c', 'name': 'f', 'line_start': 1}]
    vid = view(queue)
    queue.add_jobs(vid, [('consumer1', '')])
    jid = queue.db.execute('SELECT id FROM jobs WHERE namespace=? AND view_id=?',
                           (queue.namespace, vid)).fetchone()[0]
    queue.finish(vid, jid, 'complete', {'key': 'evidence-1'})
    rows = queue.undelivered()
    assert len(rows) == 1 and rows[0]['outcome'] == {'key': 'evidence-1'}
    assert queue.summary()['blocked_work'] == []
