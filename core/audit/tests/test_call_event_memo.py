"""Operation-local call-event reuse preserves comparator results and retries."""

from copy import deepcopy
from dataclasses import asdict

import pytest

from core.audit import consistency_dimensions as dim
from core.testing import requires_ts

SOURCE = """
int writer1(char *raw) { char *q = escape_sql(raw); validate(q); db_exec(q); return 0; }
int writer2(char *raw) { char *q = escape_sql(raw); validate(q); db_exec(q); return 0; }
int writer3(char *raw) { char *q = escape_sql(raw); validate(q); db_exec(q); return 0; }
int writer4(char *raw) { db_exec(raw); validate(raw); return 0; }
""".replace("; ", ";\n")
SINKS = {"db_exec": {"source": "test", "cwe": "CWE-89"}}
SANITIZERS = frozenset({"escape_sql"})


@requires_ts("c")
def test_two_comparators_share_only_read_events(monkeypatch):
    texts = {"a.c": SOURCE}
    expected_order = dim.detect_ordering_deviations(texts)
    expected_sanitize = dim.detect_sanitize_sink_deviations(texts, SINKS, SANITIZERS)
    assert expected_order and expected_sanitize
    original = dim._call_events_for_file
    calls = []

    def counted(*args):
        calls.append(args[0])
        return original(*args)

    monkeypatch.setattr(dim, "_call_events_for_file", counted)
    memo = dim.CallEventMemo()
    assert [asdict(x) for x in dim.detect_ordering_deviations(texts, _event_memo=memo)] == [
        asdict(x) for x in expected_order]
    saved = deepcopy(memo.events)
    assert [asdict(x) for x in dim.detect_sanitize_sink_deviations(
        texts, SINKS, SANITIZERS, _event_memo=memo)] == [asdict(x) for x in expected_sanitize]
    assert memo.events == saved
    assert calls == ["a.c"]
    texts["a.c"] = SOURCE.replace("db_exec", "otherfn")  # Same-length edit must miss.
    dim.detect_sanitize_sink_deviations(texts, SINKS, SANITIZERS, _event_memo=memo)
    assert calls == ["a.c", "a.c"]
    dim.detect_ordering_deviations(texts, _event_memo=dim.CallEventMemo())
    assert len(calls) == 3


@pytest.mark.parametrize("outcome", ["raise", "unavailable"])
def test_degraded_extraction_is_retried(monkeypatch, caplog, outcome):
    monkeypatch.setattr(dim, "_TS_AVAILABLE", True)
    calls = []

    def extract(path, source, events):
        calls.append(path)
        events[(path, "f")] = []  # Preserve partial results, too.
        if len(calls) == 1:
            if outcome == "raise":
                raise ValueError("transient extraction failure")
            return False
        return True

    monkeypatch.setattr(dim, "_call_events_for_file", extract)
    memo = dim.CallEventMemo()
    assert dim._extract_call_events({"a.c": "source"}, _memo=memo) == {("a.c", "f"): []}
    assert memo.events is None
    dim._extract_call_events({"a.c": "source"}, _memo=memo)
    assert calls == ["a.c", "a.c"]
    assert memo.events == {("a.c", "f"): []}
    assert len(caplog.records) == (1 if outcome == "raise" else 0)


@pytest.mark.parametrize("limit", ["_SHARED_EVENT_MAX_SOURCE_CHARS", "_SHARED_EVENT_MAX_EVENTS"])
def test_admission_limits_do_not_limit_extraction(monkeypatch, limit):
    monkeypatch.setattr(dim, "_TS_AVAILABLE", True)
    monkeypatch.setattr(dim, limit, 0)
    event = dim._CallEvent("sink", 1, False, frozenset(), frozenset(), "line")
    calls = []

    def extract(path, source, events):
        calls.append(path)
        events[(path, "f")] = [event]
        return True

    monkeypatch.setattr(dim, "_call_events_for_file", extract)
    memo = dim.CallEventMemo()
    for _ in range(2):
        assert dim._extract_call_events({"a.c": "source"}, _memo=memo) == {("a.c", "f"): [event]}
        assert memo.events is None
    assert calls == ["a.c", "a.c"]


@requires_ts("c")
def test_prepass_wires_reuse(monkeypatch):
    from core.audit import consistency_prepass as prepass

    original = dim._call_events_for_file
    calls = []

    def counted(*args):
        calls.append(args[0])
        return original(*args)

    monkeypatch.setattr(dim, "_call_events_for_file", counted)
    monkeypatch.setattr(prepass, "_collect_sink_vocabulary", lambda *a, **kw: SINKS)
    monkeypatch.setattr(prepass, "_collect_sanitizer_vocabulary", lambda *a: SANITIZERS)
    result = prepass.run_consistency_prepass({"a.c": SOURCE}, budget_s=360)
    assert calls == ["a.c"]
    detectors = {item["detector"] for item in result["mechanical"]}
    assert "ordering_deviation" in detectors
    assert "sanitize_sink_deviation" in detectors

    # Compare the entire prepass result with reuse disabled, including
    # finding/lead order and non-timing telemetry.
    extract = dim._extract_call_events
    monkeypatch.setattr(dim, "_extract_call_events", lambda texts, **kw: extract(texts))
    uncached = prepass.run_consistency_prepass({"a.c": SOURCE}, budget_s=360)
    assert calls == ["a.c", "a.c", "a.c"]
    result["telemetry"].pop("wall_time_s")
    uncached["telemetry"].pop("wall_time_s")
    assert result == uncached
