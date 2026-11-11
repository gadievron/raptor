"""Admission fairness is persistent and does not imply completion latency."""

from core.audit.review_fairness import ReviewAdmissionQueue


def test_three_initial_opportunities_then_continuation_across_polls():
    queue = ReviewAdmissionQueue()
    for index in range(6):
        queue.push(f'initial-{index}', 0)
    for index in range(2):
        queue.push(f'continuation-{index}', 0, continuation=True)
    selected = []
    for _ in range(8):
        # Read-only scheduler ticks cannot reset the admission counter.
        queue.state()
        queue.state()
        selected.append(queue.pop())
    assert selected == ['initial-0', 'initial-1', 'initial-2', 'continuation-0',
                        'initial-3', 'initial-4', 'initial-5', 'continuation-1']
    state = queue.state()
    assert state['initial_admissions'] == 6 and state['continuation_admissions'] == 2
    assert state['max_continuation_wait_opportunities'] == 3
    assert state['starvation_opportunities'] == 0


def test_empty_lane_yields_immediately_and_empty_poll_preserves_counters():
    queue = ReviewAdmissionQueue()
    queue.push('first', 0)
    assert queue.pop() == 'first'
    assert queue.pop() is None
    assert queue.state()['initial_since_continuation'] == 1
    queue.push('followup', 0, continuation=True)
    assert queue.pop() == 'followup'
    assert queue.state()['initial_since_continuation'] == 0
    queue.push('next', 0)
    assert queue.pop() == 'next'


def test_initial_only_admissions_cannot_build_unbounded_continuation_debt():
    queue = ReviewAdmissionQueue()
    for index in range(20):
        queue.push(str(index), 0)
        assert queue.pop() == str(index)
    assert queue.state()['initial_since_continuation'] == 3
    queue.push('initial', 0)
    queue.push('continuation-1', 0, continuation=True)
    queue.push('continuation-2', 0, continuation=True)
    assert queue.pop() == 'continuation-1'
    assert queue.pop() == 'initial'
    assert queue.pop() == 'continuation-2'


def test_continuously_arriving_high_priority_cannot_starve_older_ready_work():
    queue = ReviewAdmissionQueue()
    queue.push('old', 0)
    selected = []
    for index in range(1, 8):
        queue.push(f'urgent-{index}', float('inf'))
        selected.append(queue.pop())
        if selected[-1] == 'old':
            break
    assert 'old' in selected and selected.index('old') <= 3


def test_reprioritisation_keeps_original_age_and_delivers_once():
    queue = ReviewAdmissionQueue()
    queue.push('old', 0)
    queue.push('new', 100)
    for index in range(1000):
        queue.push('old', index)
    assert len(queue) == 2
    assert queue.pop() == 'old'
    assert queue.pop() == 'new'
    assert queue.pop() is None
    assert queue.state()['initial_admissions'] == 2


def test_discarded_or_reclassified_entries_cannot_consume_an_opportunity():
    queue = ReviewAdmissionQueue()
    queue.push('discarded', 100)
    queue.discard('discarded')
    queue.push('changed-lane', 0)
    queue.push('changed-lane', 0, continuation=True)
    assert queue.pop() == 'changed-lane'
    assert queue.pop() is None
    state = queue.state()
    assert state['initial_admissions'] == 0 and state['continuation_admissions'] == 1


def test_equal_effective_rank_keeps_older_sequence_and_snapshot_is_independent():
    queue = ReviewAdmissionQueue()
    queue.push('old', 0)
    queue.push('new', 1)
    assert queue.pop() == 'old'
    snapshot = queue.state()
    snapshot['initial_admissions'] = 999
    assert queue.state()['initial_admissions'] == 1
    assert queue.pop() == 'new'
