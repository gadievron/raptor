"""Count cursors preserve line lookup under fallback and unusual queries."""

import tracemalloc

import pytest

from core.audit.constant_resolution import _definition_line_lookup


def test_backward_queries_and_later_forward_queries():
    source = 'x\n' * 10000
    lookup = _definition_line_lookup(source)
    queries = list(range(len(source), -1, -100)) + [2, 10000, 19999, len(source)]
    assert [lookup(pos) for pos in queries] == [pos // 2 + 1 for pos in queries]


def test_unusual_queries_keep_prior_index_high_water_mark():
    source = 'x\n' * 100
    lookup = _definition_line_lookup(source)
    assert lookup(len(source)) == 101
    assert lookup(float('nan')) == 101
    assert lookup(12.5) == 7
    assert lookup(10**100) == 101
    assert lookup(-1) == 0
    assert lookup(0) == 1


def test_subclass_retains_legacy_character_search_path():
    class Source(str):
        def __len__(self):
            raise AssertionError('legacy lookup does not query text length')

    lookup = _definition_line_lookup(Source('abc\ndef\n'))
    assert lookup(4) == 2
    assert lookup(8) == 3


def test_ordered_queries_avoid_a_file_sized_line_index():
    if tracemalloc.is_tracing():
        pytest.skip('requires isolated allocation tracing')
    source = 'x\n' * 100000
    tracemalloc.start()
    try:
        lookup = _definition_line_lookup(source)
        result = lookup(len(source))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == 100001
    assert peak < 64 * 1024
