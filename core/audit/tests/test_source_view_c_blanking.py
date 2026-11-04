"""Bulk C blanking must equal the original per-character operation."""

import random
import tracemalloc

import pytest

from core.audit.source_view import _blank, _blank_c_region


@pytest.mark.parametrize("source", [
    "a" * 2050,
    "\n" * 2050,
    "a\r\n" * 700,
    "é🙂\u2028\v\x00\n" * 350,
])
def test_boundaries_newlines_and_partial_mutation_on_invalid_ranges(source):
    for start, end in [
        (0, len(source)), (1, len(source) - 1), (0, 63), (0, 64), (0, 65),
        (1023, 1025), (-1, 130), (0, len(source) + 1), (len(source), 0),
    ]:
        results = []
        for bulk in [False, True]:
            chars = list(source)
            error = None
            try:
                if bulk:
                    _blank_c_region(chars, source, start, end)
                else:
                    _blank(chars, start, end)
            except IndexError as exc:
                error = (type(exc), str(exc))
            results.append((chars, error))
        assert results[0] == results[1]


def test_generated_overlaps_preserve_original_lf_positions():
    rng = random.Random(621)
    for _ in range(300):
        source = "".join(rng.choices("abc\r\n\v\u2028é🙂", k=rng.randrange(2000)))
        expected = list(source)
        actual = list(source)
        for _ in range(10):
            start = rng.randrange(len(source) + 1)
            end = rng.randrange(start, len(source) + 1)
            _blank(expected, start, end)
            _blank_c_region(actual, source, start, end)
            assert actual == expected


def test_large_region_has_bounded_temporary_allocation():
    if tracemalloc.is_tracing():
        pytest.skip("requires isolated allocation tracing")
    source = "x" * (1024 * 1024)
    chars = list(source)
    tracemalloc.start()
    try:
        _blank_c_region(chars, source, 0, len(source))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert chars == [" "] * len(source)
    assert peak < 256 * 1024
