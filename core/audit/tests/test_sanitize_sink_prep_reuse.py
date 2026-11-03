"""Exhibit reuse preserves receipts, fallback text and operation lifetime."""

import pytest

from core.audit import consistency_dimensions as dim


def events_for_sinks(names, line=1):
    events = {}
    for index in range(4):
        events[("a.c", f"writer_{index}")] = [
            dim._CallEvent(name, line, False, frozenset(),
                           frozenset({"escape_sql"}) if index < 3 else frozenset({"raw"}),
                           "sink snippet")
            for name in names
        ]
    return events


@pytest.mark.parametrize("source,line,expected", [
    ("  escape_sql(raw);\r\nnext\n", 1, "escape_sql(raw);"),
    ("\n  é🙂\x0c embedded\r\n", 2, "é🙂\x0c embedded"),
    ("x" * 300, 1, "x" * 200),
    (" \n", 1, None), ("one\n", 10, None),
])
def test_receipts_and_split_reuse(tmp_path, monkeypatch, source, line, expected):
    names = ("db_exec", "write_out")
    monkeypatch.setattr(dim, "_extract_call_events", lambda _: events_for_sinks(names, line))
    original_split = dim.split_lines
    splits = []

    def counted(text):
        splits.append(text)
        return original_split(text)

    monkeypatch.setattr(dim, "split_lines", counted)
    sinks = {name: {"source": "context_map", "cwe": "CWE-89"} for name in names}
    for source_text in (source, "changed\n" * max(1, line)):
        splits.clear()
        results = dim.detect_sanitize_sink_deviations(
            {"a.c": source_text}, sinks, frozenset({"escape_sql"}))
        assert len(results) == 2
        assert len(splits) == 1  # Six exhibits cite the same file/line.
        for result in results:
            assert (result.n, result.conforming, result.enclosing_function) == (4, 3, "writer_3")
            receipt = result.peer_evidence
            assert receipt.deviant.snippet == "sink snippet"
            snippet = expected if source_text == source else "changed"
            assert [e.snippet for e in receipt.exhibits] == [
                snippet or f"escape_sql() dominates {result.sink}()"] * 3
            assert all((e.file, e.line) == ("a.c", line) for e in receipt.exhibits)


@pytest.mark.parametrize("sanitizers", [{"z", "a"}, frozenset({"z", "a"})])
def test_inline_choice_stays_sorted(sanitizers):
    event = dim._CallEvent("sink", 1, False, frozenset(), frozenset({"a", "z"}), "")
    assert dim._dominating_sanitizer([event], event, sanitizers) == ("a", 1)
