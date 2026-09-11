"""_function_ranges is the single checklist range walk; journal-load
failures must leave a breadcrumb instead of silently reporting zero.
"""

from unittest import mock

from core.coverage.importer import _function_ranges, import_journal

_CHECKLIST = {
    "files": [
        {
            "path": "src/a.py",
            "items": [
                {"name": "f", "line_start": 10, "line_end": 20},
                {"name": "g", "line_start": 30},          # no line_end
                {"name": None, "line_start": 40},          # unnamed → skipped
                {"line_start": 50},                        # nameless → skipped
            ],
        },
        {"items": [{"name": "h", "line_start": 1}]},       # pathless → skipped
    ],
}


def test_function_ranges_preserves_missing_hi_by_default():
    ranges = _function_ranges(_CHECKLIST)
    assert ranges == {
        ("src/a.py", "f"): (10, 20),
        ("src/a.py", "g"): (30, None),
    }


def test_function_ranges_normalise_hi_collapses_to_lo():
    ranges = _function_ranges(_CHECKLIST, normalise_hi=True)
    assert ranges[("src/a.py", "g")] == (30, 30)
    assert ranges[("src/a.py", "f")] == (10, 20)


def test_import_journal_logs_unexpected_index_failure(tmp_path, caplog):
    """Regression: an unexpected load_index failure was swallowed with a
    bare `return 0` — invisible zero LLM coverage."""
    with mock.patch(
        "core.coverage.journal.load_index",
        side_effect=PermissionError("denied"),
    ), caplog.at_level("WARNING", logger="coverage.importer"):
        marks = import_journal(mock.Mock(), tmp_path, _CHECKLIST)

    assert marks == 0
    assert any("journal index load failed" in r.message for r in caplog.records)
    assert any("PermissionError" in r.message for r in caplog.records)


def test_import_journal_edge_contract_entries_do_not_mark_caller(tmp_path):
    """Tier-1 edge-contract entries (edge_callee set) review only the
    CALL EDGE — JournalEntry.key documents that an edge review must
    never mark the caller as reviewed. Marking it made unreviewed
    callers vanish from store-derived gap listings."""
    from core.coverage.journal import ReviewJournalEntry
    from core.coverage.store import CoverageStore

    full = ReviewJournalEntry(
        ts="2026-01-01T00:00:00Z", run_id="audit-1",
        file="src/a.py", function="f", verdict="reviewed",
        source_hash="",
    )
    edge = ReviewJournalEntry(
        ts="2026-01-01T00:00:00Z", run_id="audit-1",
        file="src/a.py", function="g", verdict="reviewed",
        source_hash="", edge_callee="callee_x",
    )
    store = CoverageStore(tmp_path / "coverage.json")
    with mock.patch(
        "core.coverage.journal.load_index",
        return_value={full.key: full, edge.key: edge},
    ):
        marks = import_journal(store, tmp_path, _CHECKLIST)

    # Only the full review marked; g's range [30,30] stays a gap.
    assert marks == 1
    assert store.tool_coverage_of_range("src/a.py", 10, 20)
    assert not store.tool_coverage_of_range("src/a.py", 30, 30)
