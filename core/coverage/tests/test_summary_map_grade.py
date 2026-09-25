"""Map-grade marks in libexec/raptor-coverage-summary.

Drives the CLI as a subprocess (same pattern as test_summary_cli.py).

Grade contract under test: ``--mark --map-grade`` records examination
on the ``understand`` coverage record (llm category, SCANNED depth) —
it must never grant review credit. A plain ``--mark`` is a review
assertion and keeps its gap-suppressing behaviour. Both directions
are pinned: a map-grade-marked function stays in the review gap, a
review-marked function leaves it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from core.coverage.tests.summary_cli_support import REPO_ROOT, run_cli

_run = run_cli


def _run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "scan-1"
    d.mkdir()
    (d / ".raptor-run.json").write_text("{}")
    (d / "checklist.json").write_text(json.dumps({"target_path": "", "files": [
        {"path": "a.c", "lines": 100, "items": [
            {"name": "f1", "line_start": 1, "line_end": 20},
            {"name": "f2", "line_start": 30, "line_end": 60},
        ]}]}))
    return d


def _record(run: Path, tool: str) -> dict | None:
    path = run / f"coverage-{tool}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def test_map_grade_mark_records_understand_not_llm(tmp_path):
    run = _run_dir(tmp_path)
    r = _run(str(run), "--mark", "a.c:f1", "--map-grade")
    assert r.returncode == 0, r.stderr
    assert "examined (map-grade)" in r.stdout
    rec = _record(run, "understand")
    assert rec is not None and rec["tool"] == "understand"
    assert {"file": "a.c", "function": "f1"} in rec["functions_analysed"]
    # No review-grade record and no journaled review assertion.
    assert _record(run, "llm") is None
    assert not (run / "review-journal.jsonl").exists()


def test_map_grade_marked_function_stays_in_review_gap(tmp_path):
    """The severe direction: a map-touched, unreviewed function MUST
    still appear in the review gap — both in the CLI gap view and in
    /audit's compute_gaps (the review plan)."""
    run = _run_dir(tmp_path)
    assert _run(str(run), "--mark", "a.c:f1", "--map-grade").returncode == 0

    gaps_view = _run(str(run), "--gaps")
    assert gaps_view.returncode == 0, gaps_view.stderr
    assert "a.c:f1" in gaps_view.stdout

    sys.path.insert(0, str(REPO_ROOT))
    try:
        from core.audit.gaps import compute_gaps
        from core.coverage.record import load_records
        checklist = json.loads((run / "checklist.json").read_text())
        gaps = compute_gaps(checklist, list(load_records(run)))
    finally:
        sys.path.remove(str(REPO_ROOT))
    assert {g["name"] for g in gaps} == {"f1", "f2"}


def test_review_mark_still_deduplicates_gap(tmp_path):
    """The other direction: a genuine review assertion (plain --mark)
    keeps suppressing the function from the review plan."""
    run = _run_dir(tmp_path)
    assert _run(str(run), "--mark", "a.c:f1",
                operator=True).returncode == 0

    gaps_view = _run(str(run), "--gaps")
    assert "a.c:f1" not in gaps_view.stdout
    assert "a.c:f2" in gaps_view.stdout

    sys.path.insert(0, str(REPO_ROOT))
    try:
        from core.audit.gaps import compute_gaps
        from core.coverage.record import load_records
        checklist = json.loads((run / "checklist.json").read_text())
        gaps = compute_gaps(checklist, list(load_records(run)))
    finally:
        sys.path.remove(str(REPO_ROOT))
    assert {g["name"] for g in gaps} == {"f2"}


def test_map_grade_mark_file_ignores_statuses(tmp_path):
    run = _run_dir(tmp_path)
    mark_file = tmp_path / "map-examined-items.json"
    mark_file.write_text(json.dumps([
        {"file": "a.c", "item": "f1", "status": "suspicious"},
    ]))
    r = _run(str(run), "--mark-file", str(mark_file), "--map-grade")
    assert r.returncode == 0, r.stderr
    assert "statuses ignored" in r.stderr
    rec = _record(run, "understand")
    assert {"file": "a.c", "function": "f1"} in rec["functions_analysed"]
    assert not (run / "review-journal.jsonl").exists()


def test_map_grade_unmark_targets_understand_record(tmp_path):
    run = _run_dir(tmp_path)
    assert _run(str(run), "--mark", "a.c:f1", "--map-grade").returncode == 0
    r = _run(str(run), "--unmark", "a.c:f1", "--map-grade")
    assert r.returncode == 0, r.stderr
    rec = _record(run, "understand")
    assert rec["functions_analysed"] == []


def test_map_grade_does_not_leak_into_review_unmark(tmp_path):
    """A plain unmark keeps operating on the review record only."""
    run = _run_dir(tmp_path)
    assert _run(str(run), "--mark", "a.c:f1", "--map-grade").returncode == 0
    assert _run(str(run), "--mark", "a.c:f1",
                operator=True).returncode == 0
    r = _run(str(run), "--unmark", "a.c:f1")
    assert r.returncode == 0, r.stderr
    assert _record(run, "llm")["functions_analysed"] == []
    # The map-grade examination evidence survives untouched.
    assert {"file": "a.c", "function": "f1"} in \
        _record(run, "understand")["functions_analysed"]
