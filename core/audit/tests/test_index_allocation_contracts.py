"""Ordered aggregation contracts and bounded journal-selection memory."""

import tracemalloc

import pytest

from core.audit import journal, sibling_analysis, survival
from core.audit.journal import ReviewJournalEntry
from core.audit.source_view import _HeredocTerminators


def _entry(ts, tools, *, correction=False):
    return ReviewJournalEntry(
        ts=ts, run_id="test", file="a.c", function="work", verdict="finding",
        source_hash="", evidence_tools=tools,
        prior_review="finding" if correction else None,
        validate_verdict="confirmed" if correction else None,
    )


def test_journal_selection_preserves_first_entry_at_equal_timestamps(monkeypatch, tmp_path):
    entries = [_entry("1", ["smt:first"]), _entry("1", ["semgrep:second"]),
               _entry("3", ["codeql:future"]), _entry("2", [], correction=True)]
    monkeypatch.setattr(journal, "load_entries", lambda _: entries)
    assert survival.aggregate_survival(tmp_path) == {
        "smt": {"survived": 1, "disproven": 0, "unknown": 0}}


def test_journal_selection_does_not_copy_eligible_history(monkeypatch, tmp_path):
    if tracemalloc.is_tracing():
        pytest.skip("requires ownership of allocation tracing")
    claim = _entry("1", ["smt:claim"])
    entries = [claim] * 50000 + [_entry("2", [], correction=True)]
    monkeypatch.setattr(journal, "load_entries", lambda _: entries)
    tracemalloc.start()
    try:
        result = survival.aggregate_survival(tmp_path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == {"smt": {"survived": 1, "disproven": 0, "unknown": 0}}
    assert peak < 700 * 1024


def test_large_operation_lists_keep_first_difference_and_last_occurrence_rules():
    left = [f"left{i}" for i in range(64)]
    right = [f"right{i}" for i in range(64)]
    assert sibling_analysis.check_operation_order(
        left + ["lock", "use", "unlock"], right + ["use", "lock", "unlock"],
    ) == "Operation order differs: lock and use are swapped between siblings"
    assert sibling_analysis.check_operation_order(
        left + ["lock", "use", "lock"], right + ["use", "lock"],
    ) is None


def test_operation_list_subclass_retains_membership_override():
    class NoMembership(list):
        def __contains__(self, value):
            return False

    left = [f"left{i}" for i in range(64)] + ["lock", "use"]
    right = NoMembership([f"right{i}" for i in range(64)] + ["use", "lock"])
    assert sibling_analysis.check_operation_order(left, right) is None


def test_heredoc_index_preserves_label_order_and_certain_closers():
    source = "LABEL\nLABEL;\n  LABEL\nLABELsuffix\nother\r\nLABEL;\r\n"
    index = _HeredocTerminators(source)
    assert index.find("LABEL", 0) == (0, 5, True)
    assert index.find("LABEL", 6) == (6, 11, True)
    indented = source.index("  LABEL")
    assert index.find("LABEL", indented) == (indented, indented + 7, False)
    last = source.rindex("LABEL")
    assert index.find_certain("LABEL", indented) == (last, last + 5, True)
    assert list(index._index) == ["LABEL", "LABELsuffix", "other"]
