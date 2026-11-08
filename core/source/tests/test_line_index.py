"""Overwrite and carried-forward lookup contracts for compact line spans."""

import random

import pytest

from core.source.line_index import LineSpanIndex


def expanded(spans):
    result = {}
    for start, end, value in spans:
        for line in range(start, end + 1):
            result[line] = value
    return result


@pytest.mark.parametrize("spans", [
    [], [(4, 3, "empty")], [(-5, -2, "negative")],
    [(1, 20, "outer"), (5, 8, "inner")],
    [(5, 8, "inner"), (1, 20, "later")],
    [(1, 5, "first"), (3, 10, "second"), (6, 7, "third")],
    [(1, 2, ""), (8, 10, "next")],
], ids=["empty", "inverted", "negative", "nested", "outer-overwrite", "partial-overlap", "gaps"])
def test_lookup_matches_overwriting_dictionary(spans):
    index = LineSpanIndex(spans)
    expected = expanded(spans)
    assert bool(index) == bool(expected)
    for line in range(-8, 25):
        assert index.get(line) == expected.get(line)
        assert index.get(line, "missing") == expected.get(line, "missing")
        for floor in (-7, 1, 9):
            keys = [key for key in expected if floor <= key <= line]
            assert index.preceding(line, "missing", floor=floor) == (expected[max(keys)] if keys else "missing")


def test_generated_overlaps_match_dictionary_and_sequential_scan():
    rng = random.Random(5169)
    for _ in range(500):
        spans = [(rng.randrange(-5, 40), rng.randrange(-5, 60), str(i)) for i in range(rng.randrange(20))]
        index = LineSpanIndex(spans)
        expected = expanded(spans)
        previous = "module"
        for line in range(1, 65):
            assert index.get(line, "missing") == expected.get(line, "missing")
            previous = expected.get(line, previous)
            assert index.preceding(line, "module") == previous


def test_huge_coordinates_require_no_line_expansion():
    stop = 10**100
    index = LineSpanIndex([(1, stop, "outer"), (stop - 2, stop - 1, "inner")])
    assert index.get(stop - 2) == "inner"
    assert index.get(stop) == "outer"
    assert index.preceding(stop + 1) == "outer"
    assert index.get(stop + 1) is None


@pytest.mark.parametrize("key", [True, 1.0, 1+0j, "1", None])
def test_query_adapters_retain_dictionary_equality(key):
    index = LineSpanIndex([(1, 3, "owner")])
    assert index.get(key, "missing") == {1: "owner", 2: "owner", 3: "owner"}.get(key, "missing")


def test_unhashable_query_retains_dictionary_error():
    with pytest.raises(TypeError, match="unhashable"):
        LineSpanIndex([(1, 3, "owner")]).get([])


def test_input_records_are_snapshotted_for_native_and_adapter_queries():
    spans = [[1, 3, "owner"]]
    index = LineSpanIndex(spans)
    spans[0][2] = "changed"
    spans.append([1, 3, "later"])
    assert index.get(1) == "owner"
    assert index.get(1.0) == "owner"


@pytest.mark.parametrize("spans", [[(True, 3, "owner")], [(1, 3.0, "owner")], [(1, 3, None)]])
def test_non_native_span_data_is_rejected(spans):
    with pytest.raises(TypeError):
        LineSpanIndex(spans)
