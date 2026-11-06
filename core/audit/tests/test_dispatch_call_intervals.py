"""Catalogue call summaries retain interval boundaries, maxima and input-order ties."""

import pytest

from core.audit.cross_entry.dispatch import _catalogue_call_summaries
from core.audit.cross_entry.model import Access, Call


def access(point):
    return Access(str(point), 'f', 'a.c', 1, point, point+1, 'T', 'ctx', 'field', 'write', 'field')


def call(start, end, kinds=()):
    return Call('f', 'work', [], 1, start_byte=start, end_byte=end, argument_kinds=list(kinds))


@pytest.mark.parametrize('large', [False, True], ids=['direct', 'sweep'])
def test_nested_crossing_and_equal_spans_keep_boundaries_and_order(large):
    outer = call(0, 20, ['binary_expression', 'subscript_expression'])
    inner = call(5, 10)
    crossing = call(8, 15, ['binary_expression'])
    zero = call(9, 9, ['binary_expression'] * 20)
    reversed_span = call(12, 11, ['binary_expression'] * 20)
    equal = call(4, 9)
    calls = [outer, inner, crossing, zero, reversed_span, equal]
    if large:
        calls += [call(10000+i, 10001+i) for i in range(50)]
    points = [-1, 0, 4, 5, 8, 9, 10, 15, 20, 21]
    summaries = _catalogue_call_summaries([access(p) for p in reversed(points)], calls)
    expected = [None, outer, equal, inner, inner, inner, crossing, outer, None, None]
    assert [summaries[p][0] for p in points] == [0, 2, 2, 2, 2, 2, 2, 2, 0, 0]
    assert all(summaries[p][1] is closest for p, closest in zip(points, expected))
    assert calls[:6] == [outer, inner, crossing, zero, reversed_span, equal]


def test_sweep_expires_maximum_computed_weight():
    high = call(0, 5, ['binary_expression'] * 3)
    wide = call(0, 30, ['subscript_expression'])
    inner = call(1, 4)
    calls = [wide, high, inner] + [call(10000+i, 10001+i) for i in range(100)]
    result = _catalogue_call_summaries([access(p) for p in [2, 5, 30]], calls)
    assert result[2] == (3, inner)
    assert result[5] == (1, wide)
    assert result[30] == (0, None)


def test_large_sweep_reads_each_argument_kind_list_once():
    class Kinds(list):
        iterations = 0
        def __iter__(self):
            self.iterations += 1
            return super().__iter__()
    calls = [call(0, 100) for _ in range(20)]
    for c in calls:
        c.argument_kinds = Kinds(['binary_expression'])
    result = _catalogue_call_summaries([access(p) for p in range(20)], calls)
    assert all(result[p][0] == 1 and result[p][1] is calls[0] for p in range(20))
    assert all(c.argument_kinds.iterations == 1 for c in calls)


def test_repeated_access_positions_share_exact_summary():
    first = call(0, 10, ['binary_expression'])
    second = call(1, 11, ['subscript_expression'])
    points = [access(5) for _ in range(200)]
    assert _catalogue_call_summaries(points, [first, second]) == {5: (1, first)}


def test_empty_calls_and_empty_accesses():
    assert _catalogue_call_summaries([], [call(0, 10)]) == {}
    assert _catalogue_call_summaries([access(4), access(-1)], []) == {-1: (0, None), 4: (0, None)}
