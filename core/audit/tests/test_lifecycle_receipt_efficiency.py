"""Preserve receipt selection while bounding discarded work."""
from types import SimpleNamespace
import tracemalloc

import pytest

from core.audit import ptr_lifecycle as lifecycle
from core.audit import release_order
from core.audit.field_census import FieldRead, FieldRecord, FunctionSpan


def test_census_receipts_keep_first_three_eligible_reads():
    reads = [FieldRead("a.c", line, fn, "child", code=str(line))
             for line, fn in [(2, "event"), (4, "event"), (1, "other"),
                              (5, "event"), (6, "event"), (7, "other")]]
    census = SimpleNamespace(fields={"port": FieldRecord("port", reads=reads)})
    edge = lifecycle._AliasEdge("field", "port", "obj", "port")
    receipts = lifecycle._post_event_reads(census, edge, "event", 4)
    assert [(r["function"], r["line"], r["code"]) for r in receipts] == [
        ("other", 1, "1"), ("event", 5, "5"), ("event", 6, "6")]


def test_local_receipts_keep_coordinates_and_assignment_filter():
    edge = lifecycle._AliasEdge("local", "alias", "obj", "port")
    span = FunctionSpan("event", 10, 17)
    lines = ["alias = value;", "use(alias);", "alias == other;",
             "alias_more;", "return alias;", "use(alias);"]
    receipts = lifecycle._local_post_event_reads(edge, lines, span, 0)
    assert [(r["line"], r["code"]) for r in receipts] == [
        (11, "use(alias);"), (12, "alias == other;"), (14, "return alias;")]
    assert all(r["function"] == "event" and r["context"] == "expr"
               for r in receipts)
    assert lifecycle._local_post_event_reads(edge, lines, span, 20) == []


@pytest.mark.parametrize("local", [False, True])
def test_receipt_collection_has_bounded_temporary_allocation(local):
    if tracemalloc.is_tracing():
        pytest.skip("requires ownership of allocation tracing")
    edge = lifecycle._AliasEdge("local" if local else "field", "alias", "obj", "port")
    lines = ["use(alias);"] * 20000
    read = FieldRead("a.c", 2, "other", "child")
    census = SimpleNamespace(fields={"alias": FieldRecord("alias", reads=[read] * 20000)})
    span = FunctionSpan("event", 1, len(lines))
    tracemalloc.start()
    try:
        receipts = (lifecycle._local_post_event_reads(edge, lines, span, 0) if local
                    else lifecycle._post_event_reads(census, edge, "event", 1))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(receipts) == 3
    assert peak < 128 * 1024


def test_event_code_remains_per_match_for_string_subclasses():
    class Line(str):
        calls = 0

        def strip(self):
            self.calls += 1
            return f"receipt {self.calls}"

    line = Line("free(obj->first); free(obj -> second);")
    events = lifecycle._find_events([line], 9, None)
    assert [(e["target_expr"], e["target_field"], e["code"]) for e in events] == [
        ("obj->first", "first", "receipt 1"),
        ("obj->second", "second", "receipt 2")]


def test_release_classification_and_status_order():
    assert release_order._classify_destination(
        "tmp", ["noise", "tmp = cond ? out : malloc(8);"], ("out",)) == "unresolved"
    assert release_order._classify_destination(
        "tmp", ["noise", "tmp = malloc(8);"], ("out",)) == "internal"
    assert release_order._status_bindings(
        ["noise", "ok = finish(ctx);", "ok = finish(ctx);", "other = finish(ctx);"],
        7, "finish") == (["finish", "ok", "other"], 8)
