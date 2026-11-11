"""Cost scheduling controls for admission opportunities, not completion time."""

import pytest

from core.audit.review_fairness import ReviewAdmissionQueue
from core.audit.task_graph import TaskGraph


def _gap(name):
    return {'file': 'cost.py', 'name': name, 'line_start': 0, 'priority_score': 0}


def _key(name):
    return f'cost.py:{name}:0'


def _names(tasks):
    return [task.gap['name'] for task in tasks]


@pytest.mark.parametrize('fairness', [False, True], ids=['legacy-cost', 'fair-cost'])
def test_cost_duration_and_urgent_control(fairness):
    graph = TaskGraph.from_workqueue(
        [_gap('short'), _gap('long'), _gap('medium')], [], schedule='cost',
        duration_hints={_key('short'): 1, _key('long'): 1000, _key('medium'): 50},
        review_fairness=fairness,
    )
    assert graph.inject_task(_key('followup'), _gap('followup'), 100,
                             continuation=True)
    expected = (['short', 'long', 'medium', 'followup'] if fairness else
                ['followup', 'long', 'medium', 'short'])
    assert _names(graph.pop_ready(10)) == expected
    assert graph.pop_ready() == []
    assert graph.review_fairness_enabled is fairness
    if fairness:
        assert graph.admission_state()['initial_admissions'] == 3
        assert graph.admission_state()['continuation_admissions'] == 1
    else:
        assert graph.admission_state() == {'policy_version': 'legacy'}


def test_cost_mixed_polls_keep_three_to_one_opportunities():
    names = [f'initial-{i}' for i in range(6)]
    graph = TaskGraph.from_workqueue(
        [_gap(name) for name in names], [], schedule='cost', review_fairness=True,
        duration_hints={_key(name): 10 ** i for i, name in enumerate(names)},
    )
    queue = ReviewAdmissionQueue()
    for name in names:
        queue.push(_key(name), 0)
    for i in range(2):
        name = f'followup-{i}'
        assert graph.inject_task(_key(name), _gap(name), 100 + i, continuation=True)
        queue.push(_key(name), 100 + i, continuation=True)
    trace = []
    for size in (2, 1, 0, 2, 1, 2):
        before = graph.admission_state()
        assert graph.admission_state() == before
        batch = graph.pop_ready(size)
        assert [task.key for task in batch] == [queue.pop() for _ in range(size)]
        trace.extend(_names(batch))
        assert graph.admission_state() == queue.state()
    assert trace == ['initial-0', 'initial-1', 'initial-2', 'followup-0',
                     'initial-3', 'initial-4', 'initial-5', 'followup-1']
    assert graph.pop_ready(10) == []
    assert queue.pop() is None
    state = graph.admission_state()
    assert state['max_continuation_wait_opportunities'] == 3
    assert state['starvation_opportunities'] == 0


@pytest.mark.parametrize('continuation', [False, True], ids=['initial', 'continuation'])
def test_cost_urgent_reprioritisation_preserves_bounded_fifo_age(continuation):
    graph = TaskGraph.from_workqueue(
        [], [], schedule='cost', review_fairness=True,
        duration_hints={_key('old'): 1, **{_key(f'urgent-{i}'): 1000 + i for i in range(6)}},
    )
    assert graph.inject_task(_key('old'), _gap('old'), 0, continuation=continuation)
    trace = []
    for i in range(6):
        name = f'urgent-{i}'
        # Every revision is urgent in legacy cost mode; none may renew FIFO age.
        for priority in range(100, 200):
            assert graph.inject_task(_key(name), _gap(name), priority,
                                     continuation=continuation)
        trace.extend(_names(graph.pop_ready()))
    assert trace == ['urgent-0', 'urgent-1', 'old', 'urgent-2', 'urgent-3', 'urgent-4']
    assert _names(graph.pop_ready(100)) == ['urgent-5']
    assert graph.pop_ready(100) == []
    state = graph.admission_state()
    assert state['continuation_admissions' if continuation else 'initial_admissions'] == 7
    assert state['initial_admissions' if continuation else 'continuation_admissions'] == 0
    assert state['starvation_opportunities'] == 0


def test_cost_fairness_keeps_dependencies_issued_exclusion_and_requeue_cap():
    graph = TaskGraph.from_workqueue(
        [_gap('caller'), _gap('callee')],
        [{'caller_file': 'cost.py', 'caller': 'caller',
          'callee_file': 'cost.py', 'callee': 'callee'}],
        schedule='cost', review_fairness=True,
        duration_hints={_key('caller'): 1000, _key('callee'): 1},
    )
    assert graph.inject_task(_key('caller'), _gap('caller'), 100, continuation=True)
    callee, = graph.pop_ready(10)
    assert callee.key == _key('callee')
    assert graph.admission_state()['continuation_admissions'] == 0
    assert graph.pop_ready(10) == []
    assert graph.mark_complete(callee.key) == [_key('caller')]
    caller, = graph.pop_ready(10)
    assert caller.key == _key('caller')
    before = graph.admission_state()
    for priority in range(200, 210):
        assert graph.inject_task(caller.key, _gap('caller'), priority, continuation=True)
    assert graph.pop_ready(10) == []
    assert graph.admission_state() == before
    graph.mark_complete(caller.key)
    assert not graph.inject_task(caller.key, _gap('caller'), 300)
    assert graph.inject_task(caller.key, _gap('caller'), 300, requeue=True)
    assert _names(graph.pop_ready(10)) == ['caller']
    assert graph.pop_ready(10) == []
    graph.mark_complete(caller.key)
    assert not graph.inject_task(caller.key, _gap('caller'), 400, requeue=True)
    assert graph.pop_ready(10) == []
    state = graph.admission_state()
    assert state['initial_admissions'] == 1
    assert state['continuation_admissions'] == 2
    assert graph.pending == 0


def test_cost_empty_lanes_yield_without_poll_reset_or_admission_debt():
    graph = TaskGraph.from_workqueue([], [], schedule='cost', review_fairness=True)
    for i in range(10):
        name = f'initial-{i}'
        assert graph.inject_task(_key(name), _gap(name), 0)
        assert _names(graph.pop_ready(10)) == [name]
        graph.mark_complete(_key(name))
        before = graph.admission_state()
        assert graph.pop_ready(10) == []
        assert graph.admission_state() == before
    assert graph.admission_state()['initial_since_continuation'] == 3
    assert graph.inject_task(_key('initial'), _gap('initial'), 0)
    for i in range(2):
        assert graph.inject_task(_key(f'followup-{i}'), _gap(f'followup-{i}'), 100,
                                 continuation=True)
    assert _names(graph.pop_ready(1)) == ['followup-0']
    assert _names(graph.pop_ready(1)) == ['initial']
    assert _names(graph.pop_ready(10)) == ['followup-1']
    before = graph.admission_state()
    assert graph.pop_ready(10) == []
    assert graph.admission_state() == before
    assert before['initial_admissions'] == 11
    assert before['continuation_admissions'] == 2
    assert before['initial_since_continuation'] == 0
