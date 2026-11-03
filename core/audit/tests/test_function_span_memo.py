"""Span reuse preserves comparator inputs, retries and retention limits."""

from copy import deepcopy
from dataclasses import asdict

import pytest

from core.audit import consistency_dimensions as dim
from core.audit.sibling_analysis import SiblingGroup, SiblingPath
from core.testing import requires_ts


def fixture():
    names = [f"op_{index}" for index in range(4)]
    parts = []
    for index, name in enumerate(names):
        checks = ('if (!check_permission("admin")) return -1;\n'
                  'if (!e) return -1;\nfree_buffer(buf);\n') if index < 3 else ""
        parts.append(f"int {name}(req_t *r) {{\nvoid *buf = alloc_buffer();\n"
                     f"entry_t *e = lookup_entry(r);\n{checks}return e->value;\n}}")
    texts = {"a.c": "\n".join(parts)}
    pair = dim.LearnedPair("alloc_buffer", "free_buffer", "alloc_free", "domain_model", "test")
    group = SiblingGroup(group_id="test", sibling_type="dispatch_site", description="test",
                         siblings=[SiblingPath(label=n, file="a.c", function=n) for n in names])
    return texts, pair, group


@requires_ts("c")
def test_all_three_comparators_share_read_only_spans(monkeypatch):
    texts, pair, group = fixture()

    def compare(memo):
        return [dim.detect_cleanup_deviations(texts, [pair], _span_memo=memo),
                dim.detect_interface_deviations(texts, [group], _span_memo=memo),
                dim.detect_guard_presence_deviations(texts, _span_memo=memo)]

    expected = compare(None)
    assert all(expected)
    calls = []
    extract = dim._function_spans_for_file

    def counted(*args):
        calls.append(args[0])
        return extract(*args)

    monkeypatch.setattr(dim, "_function_spans_for_file", counted)
    memo = dim.FunctionSpanMemo()
    dim._function_spans(texts, _memo=memo)
    saved = deepcopy(memo.spans)
    actual = compare(memo)
    assert calls == ["a.c"]
    assert memo.spans == saved
    assert [[asdict(x) for x in group] for group in actual] == [
        [asdict(x) for x in group] for group in expected]
    texts["a.c"] = texts["a.c"].replace("op_0", "op_x")
    assert dim._function_spans(texts, _memo=memo)[0][1] == "op_x"
    assert calls == ["a.c", "a.c"]
    dim._function_spans(texts, _memo=dim.FunctionSpanMemo())
    assert len(calls) == 3


@pytest.mark.parametrize("outcome", ["raise", "degraded"])
def test_failed_or_degraded_extraction_retries(monkeypatch, caplog, outcome):
    monkeypatch.setattr(dim, "_TS_AVAILABLE", True)
    calls = []
    row = ("a.c", "f", 1, ["body"])

    def extract(path, source, spans):
        calls.append(path)
        spans.append(row)
        if len(calls) == 1:
            if outcome == "raise":
                raise ValueError("transient failure")
            return False
        return True

    monkeypatch.setattr(dim, "_function_spans_for_file", extract)
    memo = dim.FunctionSpanMemo()
    assert dim._function_spans({"a.c": "source"}, _memo=memo) == [row]
    assert memo.spans is None
    assert dim._function_spans({"a.c": "source"}, _memo=memo) == [row]
    assert calls == ["a.c", "a.c"]
    assert memo.spans == [row]
    assert len(caplog.records) == (1 if outcome == "raise" else 0)


@pytest.mark.parametrize("limit", ["_SHARED_SPAN_MAX_CHARS", "_SHARED_SPAN_MAX_FUNCTIONS",
                                  "_SHARED_SPAN_MAX_LINES"])
def test_limits_only_disable_reuse(monkeypatch, limit):
    monkeypatch.setattr(dim, "_TS_AVAILABLE", True)
    monkeypatch.setattr(dim, limit, 0)
    calls = []
    row = ("a.c", "f", 1, ["body"])

    def extract(path, source, spans):
        calls.append(path)
        spans.append(row)
        return True

    monkeypatch.setattr(dim, "_function_spans_for_file", extract)
    memo = dim.FunctionSpanMemo()
    for _ in range(2):
        assert dim._function_spans({"a.c": "source"}, _memo=memo) == [row]
        assert memo.spans is None
    assert calls == ["a.c", "a.c"]


@requires_ts("c")
def test_prepass_wires_reuse_and_preserves_results(monkeypatch):
    from core.audit import consistency_prepass as prepass

    texts, pair, group = fixture()
    monkeypatch.setattr(dim, "learned_cleanup_pairs", lambda *args: [pair])
    original = dim._function_spans_for_file
    calls = []

    def counted(*args):
        calls.append(args[0])
        return original(*args)

    monkeypatch.setattr(dim, "_function_spans_for_file", counted)
    cached = prepass.run_consistency_prepass(texts, peer_groups=[group], budget_s=360)
    # Other unmodified prepass consumers also extract spans; count the
    # exact reduction rather than assuming these three are the only ones.
    cached_calls = len(calls)
    extract = dim._function_spans
    monkeypatch.setattr(dim, "_function_spans", lambda texts, **kw: extract(texts))
    calls.clear()
    uncached = prepass.run_consistency_prepass(texts, peer_groups=[group], budget_s=360)
    assert len(calls) == cached_calls + 2
    cached["telemetry"].pop("wall_time_s")
    uncached["telemetry"].pop("wall_time_s")
    assert cached == uncached


@pytest.mark.parametrize("limit,value,rows", [
    ("_SHARED_SPAN_MAX_CHARS", 8, [("a.c", "f", 1, ["x" * 9])]),
    ("_SHARED_SPAN_MAX_FUNCTIONS", 1,
     [("a.c", "f", 1, ["x"]), ("a.c", "g", 2, ["y"])]),
    ("_SHARED_SPAN_MAX_LINES", 1, [("a.c", "f", 1, ["x", "y"])]),
])
def test_output_limits_include_duplicated_bodies(monkeypatch, limit, value, rows):
    monkeypatch.setattr(dim, "_TS_AVAILABLE", True)
    monkeypatch.setattr(dim, limit, value)

    def extract(path, source, spans):
        spans.extend(rows)
        return True

    monkeypatch.setattr(dim, "_function_spans_for_file", extract)
    memo = dim.FunctionSpanMemo()
    assert dim._function_spans({"a.c": "x"}, _memo=memo) == rows
    assert memo.spans is None


@requires_ts("c")
def test_input_order_remains_part_of_reuse_key():
    memo = dim.FunctionSpanMemo()
    first = dim._function_spans({"a.c": "void a() {}", "b.c": "void b() {}"}, _memo=memo)
    second = dim._function_spans({"b.c": "void b() {}", "a.c": "void a() {}"}, _memo=memo)
    assert [row[1] for row in first] == ["a", "b"]
    assert [row[1] for row in second] == ["b", "a"]
