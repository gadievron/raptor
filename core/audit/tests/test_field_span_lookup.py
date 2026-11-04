"""Function lookup must keep inclusive bounds and first-match priority."""

import random

import pytest

from core.audit.field_census import FunctionSpan, _span_for_line, _span_lookup


@pytest.mark.parametrize("ranges", [
    [], [(3, 5)], [(1, 4), (8, 10)],
    [(1, 20), (3, 5), (8, 10), (21, 25)],
    [(1, 3), (1, 10), (2, 15)],
    [(1, 10), (3, 10), (7, 10)],
    [(8, 10), (1, 20), (3, 5)],
    [(-5, -1), (1, 4), (6, 3), (8, 10)],
])
def test_inclusive_ranges_and_first_match(ranges):
    spans = [FunctionSpan(str(i), start, end) for i, (start, end) in enumerate(ranges)]
    lookup = _span_lookup(spans)
    for line in range(-7, 28):
        assert lookup(line) is _span_for_line(spans, line)


def test_generated_overlaps_and_unordered_ranges():
    rng = random.Random(721)
    for _ in range(300):
        spans = [
            FunctionSpan(str(i), rng.randrange(-5, 50), rng.randrange(-5, 70))
            for i in range(rng.randrange(40))
        ]
        if rng.choice((True, False)):
            spans.sort(key=lambda span: span.start)
        lookup = _span_lookup(spans)
        for line in range(-7, 73):
            assert lookup(line) is _span_for_line(spans, line)


@pytest.mark.parametrize("tier", ["ts", "regex"])
def test_scanners_attribute_accesses_across_indexed_functions(tier):
    from core.audit import field_census as fc
    from core.audit.callsite_consistency import parse_source_cached

    count = fc._SPAN_LOOKUP_MIN_SPANS + 2
    source = "\n".join(
        f"void f{i}(struct Obj *obj) {{ obj->target = obj->value; }}"
        for i in range(count)
    )
    raw = {}
    if tier == "ts":
        tree, _ = parse_source_cached("many.c", source)
        if tree is None:
            pytest.skip("tree-sitter C grammar unavailable")
        fc._scan_file_ts(tree, source, "many.c", raw, lambda name: True)
        order = reversed(range(count))
    else:
        fc._scan_file_regex(source, "many.c", raw, lambda name: True)
        order = range(count)
    assert [(site.function, site.line) for site in raw["target"].writes] == [
        (f"f{i}", i + 1) for i in order
    ]
