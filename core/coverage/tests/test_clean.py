"""Tests for coverage-aware /project clean (snapshot + classify + retained flip)."""

from __future__ import annotations

import json

from core.coverage.clean import (
    apply_removal,
    classify_removal,
    clean_run,
    dedup_runs,
    format_consequence,
)
from core.coverage.store import CoverageStore

_CHECKLIST = {
    "files": [
        {"path": "a.c", "total_lines": 100, "items": [
            {"name": "f1", "line_start": 0, "line_end": 20},
            {"name": "f2", "line_start": 30, "line_end": 60},
        ]},
    ],
}


def _store(tmp_path):
    return CoverageStore(tmp_path / "coverage.json", target="zip:abc")


def _run(tmp_path, name, files_examined, findings=None):
    d = tmp_path / name
    d.mkdir()
    (d / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": files_examined, "timestamp": "t"}))
    if findings is not None:
        (d / "findings.json").write_text(json.dumps(findings))
    return d


def test_duplicate_run_is_free(tmp_path):
    s = _store(tmp_path)
    victim = _run(tmp_path, "old", ["a.c"], findings=[])
    survivor = _run(tmp_path, "new", ["a.c"], findings=[])
    c = clean_run(s, victim, [survivor], _CHECKLIST)
    assert c.duplicate is True and c.lossy is False
    assert "free to remove" in format_consequence(c)


def test_sole_source_clean_coverage_preserved(tmp_path):
    s = _store(tmp_path)
    # victim examined a.c clean; no survivor examined it.
    victim = _run(tmp_path, "old", ["a.c"], findings=[])
    c = clean_run(s, victim, [], _CHECKLIST)
    assert c.duplicate is False and c.lossy is False
    # Coverage snapshotted -> f1/f2 are now examined-clean in the store.
    assert s.function_verdict("a.c", 0, 20) == "clean"
    assert "preserved into the store" in format_consequence(c)


def test_sole_source_finding_becomes_found_then_lost(tmp_path):
    s = _store(tmp_path)
    victim = _run(tmp_path, "old", ["a.c"],
                  findings=[{"id": "F1", "file": "a.c", "line": 42}])  # in f2
    c = clean_run(s, victim, [], _CHECKLIST)
    assert c.lossy is True and len(c.findings_lost) == 1
    assert s.function_verdict("a.c", 30, 60) == "found_then_lost"
    assert "re-review gaps" in format_consequence(c)


def test_classify_is_read_only_then_apply_mutates(tmp_path):
    # classify needs no store and doesn't touch one; apply does the snapshot.
    victim = _run(tmp_path, "old", ["a.c"],
                  findings=[{"id": "F1", "file": "a.c", "line": 42}])
    c = classify_removal(victim, [])
    assert c.lossy is True
    s = _store(tmp_path)
    assert s.function_verdict("a.c", 30, 60) == "unexamined"   # untouched by classify
    apply_removal(s, victim, _CHECKLIST, c)
    assert s.function_verdict("a.c", 30, 60) == "found_then_lost"


def test_finding_also_in_survivor_stays_open(tmp_path):
    s = _store(tmp_path)
    finding = [{"id": "F1", "file": "a.c", "line": 42}]
    victim = _run(tmp_path, "old", ["a.c"], findings=finding)
    survivor = _run(tmp_path, "new", ["a.c"], findings=finding)  # same location
    c = clean_run(s, victim, [survivor], _CHECKLIST)
    assert c.findings_lost == []          # survivor still holds it
    assert s.function_verdict("a.c", 30, 60) == "open"
    assert c.duplicate is True            # same files + same findings


def test_dedup_drops_older_identical_keeps_newest(tmp_path):
    # Three identical runs (name order = chronological): drop the two older.
    a = _run(tmp_path, "run-01", ["a.c"], findings=[])
    b = _run(tmp_path, "run-02", ["a.c"], findings=[])
    c = _run(tmp_path, "run-03", ["a.c"], findings=[])
    droppable, reasons = dedup_runs([c, a, b])   # order-insensitive
    assert set(d.name for d in droppable) == {"run-01", "run-02"}
    assert all(r.duplicate for r in reasons)


def test_dedup_keeps_run_with_unique_findings(tmp_path):
    # run-01 holds a finding; run-02 (same files, no findings) adds nothing ->
    # run-02 is the droppable one, the finding-bearing run is kept.
    a = _run(tmp_path, "run-01", ["a.c"],
             findings=[{"id": "F1", "file": "a.c", "line": 42}])
    b = _run(tmp_path, "run-02", ["a.c"], findings=[])
    droppable, _ = dedup_runs([a, b])
    assert [d.name for d in droppable] == ["run-02"]


def test_dedup_keeps_both_when_each_has_a_unique_finding(tmp_path):
    a = _run(tmp_path, "run-01", ["a.c"],
             findings=[{"id": "F1", "file": "a.c", "line": 42}])
    b = _run(tmp_path, "run-02", ["a.c"],
             findings=[{"id": "F2", "file": "a.c", "line": 10}])
    droppable, _ = dedup_runs([a, b])
    assert droppable == []                       # neither subsumes the other


def test_dedup_keeps_run_with_unique_coverage(tmp_path):
    a = _run(tmp_path, "run-01", ["a.c", "b.c"], findings=[])
    b = _run(tmp_path, "run-02", ["a.c"], findings=[])
    droppable, _ = dedup_runs([a, b])
    # run-02's files (a.c) ⊆ run-01's -> run-02 droppable; run-01 has unique b.c.
    assert [d.name for d in droppable] == ["run-02"]


def test_dedup_single_run_kept(tmp_path):
    a = _run(tmp_path, "run-01", ["a.c"], findings=[])
    assert dedup_runs([a]) == ([], [])


def test_distinct_findings_same_line_not_collapsed(tmp_path):
    # Two different issues at a.c:42; the survivor holds only one. Without an
    # issue discriminator both key as (a.c, L42), so xss would look "covered"
    # by the survivor's sqli and be silently lost. It must be flagged lost.
    victim = _run(tmp_path, "old", ["a.c"], findings=[
        {"file": "a.c", "line": 42, "rule_id": "sqli"},
        {"file": "a.c", "line": 42, "rule_id": "xss"}])
    survivor = _run(tmp_path, "new", ["a.c"], findings=[
        {"file": "a.c", "line": 42, "rule_id": "sqli"}])
    c = classify_removal(victim, [survivor])
    assert c.lossy is True and len(c.findings_lost) == 1


def test_idless_finding_flip_targets_same_entry(tmp_path):
    # Backfill links findings retained=True; a clean snapshot must FLIP the
    # same entries to retained=False, not append duplicates. The index-1
    # finding is the regression: a position-dependent fallback id gave it a
    # different id across the two link paths, leaving a stale retained=True
    # entry that kept the verdict 'open' instead of 'found_then_lost'.
    from core.coverage.importer import import_run_dir, import_run_findings
    s = _store(tmp_path)
    victim = _run(tmp_path, "old", ["a.c"], findings=[
        {"file": "a.c", "line": 10, "rule_id": "a"},    # f1 (0-20), index 0
        {"file": "a.c", "line": 42, "rule_id": "b"}])   # f2 (30-60), index 1
    import_run_dir(s, victim, _CHECKLIST)
    import_run_findings(s, victim)                       # retained=True (backfill)
    clean_run(s, victim, [], _CHECKLIST)                 # apply: flip to retained=False
    assert s.function_verdict("a.c", 0, 20) == "found_then_lost"
    assert s.function_verdict("a.c", 30, 60) == "found_then_lost"
