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
