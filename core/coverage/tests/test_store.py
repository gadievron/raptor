"""Tests for the Phase 3 persistent CoverageStore (core/coverage/store.py)."""

from __future__ import annotations

from core.coverage.store import CoverageStore, _coalesce


def _store(tmp_path):
    return CoverageStore(tmp_path / "coverage.json", target="zip:abc123")


# --- interval coalescing ---------------------------------------------------


def test_coalesce_merges_overlapping_and_adjacent():
    assert _coalesce([[0, 5], [3, 8]]) == [[0, 8]]        # overlap
    assert _coalesce([[0, 5], [6, 9]]) == [[0, 9]]        # adjacent (5,6)
    assert _coalesce([[0, 5], [10, 12]]) == [[0, 5], [10, 12]]  # disjoint
    assert _coalesce([[10, 12], [0, 5]]) == [[0, 5], [10, 12]]  # unsorted in
    assert _coalesce([]) == []


# --- mark() + delta --------------------------------------------------------


def test_mark_returns_newly_covered_delta(tmp_path):
    s = _store(tmp_path)
    assert s.mark("a.c", 0, 9, "semgrep") == 10        # 10 fresh lines
    assert s.mark("a.c", 0, 9, "semgrep") == 0         # all already covered
    assert s.mark("a.c", 5, 14, "semgrep") == 5        # only 10..14 are new
    assert s.mark("a.c", 0, 9, "codeql") == 10         # different tool = fresh


def test_mark_tolerates_swapped_bounds(tmp_path):
    s = _store(tmp_path)
    assert s.mark("a.c", 9, 0, "semgrep") == 10


def test_mark_coalesces_into_one_interval(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 5, "semgrep")
    s.mark("a.c", 6, 9, "semgrep")          # adjacent
    assert s.covered_lines("a.c") == [[0, 9]]


# --- queries ---------------------------------------------------------------


def test_who_checked(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 50, "semgrep")
    s.mark("a.c", 30, 89, "claude:audit")
    assert s.who_checked("a.c", 40) == ["claude:audit", "semgrep"]
    assert s.who_checked("a.c", 10) == ["semgrep"]
    assert s.who_checked("a.c", 200) == []
    assert s.who_checked("missing.c", 1) == []


def test_file_coverage_needs_total_lines(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 49, "semgrep")          # 50 lines
    assert s.file_coverage("a.c") == 0.0     # total_lines unknown -> 0
    s.set_file_meta("a.c", total_lines=100)
    assert s.file_coverage("a.c") == 50.0
    s.mark("a.c", 50, 99, "codeql")          # union now full
    assert s.file_coverage("a.c") == 100.0


def test_covered_lines_unions_across_tools(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 10, "semgrep")
    s.mark("a.c", 8, 20, "claude:audit")
    assert s.covered_lines("a.c") == [[0, 20]]


def test_link_finding_dedups(tmp_path):
    s = _store(tmp_path)
    s.link_finding("a.c", "FIND-1")
    s.link_finding("a.c", "FIND-1")
    s.link_finding("a.c", "FIND-2")
    assert s.finding_ids("a.c") == ["FIND-1", "FIND-2"]


# --- persistence -----------------------------------------------------------


def test_save_load_roundtrip(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 9, "semgrep")
    s.mark("a.c", 30, 89, "claude:audit")
    s.set_file_meta("a.c", total_lines=100, sloc=80)
    s.link_finding("a.c", "FIND-1")
    path = s.save()
    assert path.exists()

    reloaded = CoverageStore(path)
    assert reloaded.target == "zip:abc123"        # persisted, not re-supplied
    assert reloaded.who_checked("a.c", 40) == ["claude:audit"]
    assert reloaded.file_coverage("a.c") == 70.0  # (10 + 60) / 100 union
    assert reloaded.finding_ids("a.c") == ["FIND-1"]
    assert reloaded.files() == ["a.c"]


def test_load_keeps_persisted_target_over_constructor_arg(tmp_path):
    s = CoverageStore(tmp_path / "coverage.json", target="git:deadbeef")
    s.mark("a.c", 0, 1, "semgrep")
    s.save()
    # A later run that passes a different target must not clobber the
    # store's recorded identity.
    reopened = CoverageStore(tmp_path / "coverage.json", target="git:OTHER")
    assert reopened.target == "git:deadbeef"


# --- inventory-join queries (step 2) ---------------------------------------

_CHECKLIST = {
    "files": [
        {"path": "a.c", "sha256": "x", "lines": 100, "sloc": 80,
         "items": [
             {"name": "f1", "line_start": 0, "line_end": 20},
             {"name": "f2", "line_start": 30, "line_end": 60},
         ]},
        {"path": "b.c", "sha256": "y", "lines": 50,
         "functions": [   # fallback key
             {"name": "g1", "line_start": 0, "line_end": 10},
         ]},
    ],
}


def test_iter_inventory_functions_handles_items_and_functions():
    from core.coverage.store import iter_inventory_functions
    got = list(iter_inventory_functions(_CHECKLIST))
    # 5th element is kind; legacy items without a kind default to "function".
    assert got == [
        ("a.c", "f1", 0, 20, "function"),
        ("a.c", "f2", 30, 60, "function"),
        ("b.c", "g1", 0, 10, "function"),
    ]


def test_who_checked_function_full_vs_partial(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 20, "semgrep")          # all of f1
    s.mark("a.c", 30, 44, "claude:audit")    # 15 of f2's 31 lines
    assert s.who_checked_function("a.c", 0, 20) == {"semgrep": "full"}
    assert s.who_checked_function("a.c", 30, 60) == {"claude:audit": "partial (48%)"}


def test_function_covered_with_category(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 20, "semgrep")          # f1: static only
    s.mark("a.c", 30, 60, "claude:audit")    # f2: llm
    assert s.function_covered("a.c", 0, 20) is True
    assert s.function_covered("a.c", 0, 20, category="llm") is False
    assert s.function_covered("a.c", 30, 60, category="llm") is True


def test_unchecked_functions_overall_and_by_category(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 20, "semgrep")          # f1 scanned (static)
    s.mark("a.c", 30, 60, "claude:audit")    # f2 analysed (llm)
    # b.c/g1 untouched by anything.
    assert s.unchecked_functions(_CHECKLIST) == [("b.c", "g1", 0)]
    # The /audit gap: functions no LLM has examined -> f1 (semgrep only) + g1.
    assert s.unchecked_functions(_CHECKLIST, category="llm") == [
        ("a.c", "f1", 0),
        ("b.c", "g1", 0),
    ]


def test_unchecked_functions_handles_missing_line_end(tmp_path):
    s = _store(tmp_path)
    checklist = {"files": [{"path": "c.c", "items": [
        {"name": "h", "line_start": 5, "line_end": None}]}]}
    assert s.unchecked_functions(checklist) == [("c.c", "h", 5)]
    s.mark("c.c", 5, 5, "semgrep")           # cover the declaration line
    assert s.unchecked_functions(checklist) == []


def test_import_inventory_meta_enables_file_coverage(tmp_path):
    s = _store(tmp_path)
    s.import_inventory_meta(_CHECKLIST)
    s.mark("a.c", 0, 49, "semgrep")          # 50 of 100 lines
    assert s.file_coverage("a.c") == 50.0


# --- verdict-bearing coverage (the three states) ---------------------------


def test_function_verdict_four_states(tmp_path):
    s = _store(tmp_path)
    # f1 [0,20]: examined, no finding -> clean
    s.mark("a.c", 0, 20, "semgrep")
    assert s.function_verdict("a.c", 0, 20) == "clean"
    # f2 [30,60]: examined + a retained finding inside -> open
    s.mark("a.c", 30, 60, "semgrep")
    s.link_finding("a.c", "F1", line=42, retained=True)
    assert s.function_verdict("a.c", 30, 60) == "open"
    # flip the finding's detail to lost -> found_then_lost
    s.link_finding("a.c", "F1", line=42, retained=False)
    assert s.function_verdict("a.c", 30, 60) == "found_then_lost"
    # never examined -> unexamined
    assert s.function_verdict("b.c", 0, 10) == "unexamined"


def test_finding_without_line_does_not_set_function_verdict(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 20, "semgrep")
    s.link_finding("a.c", "F1")              # no line -> can't attribute
    assert s.function_verdict("a.c", 0, 20) == "clean"
    assert s.finding_ids("a.c") == ["F1"]    # still a file-level signal


def test_finding_implies_examined_without_coverage_record(tmp_path):
    # A finding IS examination evidence: a function with an in-range finding
    # must never read 'unexamined' just because no whole-file coverage record
    # happens to cover its line. open (retained) / found_then_lost (not).
    s = _store(tmp_path)
    s.link_finding("a.c", "F1", line=42, retained=True)     # no mark() at all
    assert s.function_verdict("a.c", 30, 60) == "open"
    s.link_finding("a.c", "F1", line=42, retained=False)
    assert s.function_verdict("a.c", 30, 60) == "found_then_lost"
    # a sibling range with neither finding nor coverage is still unexamined
    assert s.function_verdict("a.c", 0, 20) == "unexamined"


def test_review_gap_includes_unexamined_and_found_then_lost(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 20, "semgrep")          # f1 clean
    s.mark("a.c", 30, 60, "semgrep")
    s.link_finding("a.c", "F1", line=42, retained=False)   # f2 found_then_lost
    # b.c/g1 unexamined
    gap = s.review_gap(_CHECKLIST)
    assert gap == [
        ("a.c", "f2", 30, "found_then_lost"),
        ("b.c", "g1", 0, "unexamined"),
    ]


def test_coverage_store_lock_excludes_other_process(tmp_path):
    import subprocess
    import sys

    from core.coverage.store import _HAS_FCNTL, coverage_store_lock

    if not _HAS_FCNTL:
        return                                   # no-op lock on non-POSIX
    cov = tmp_path / "coverage.json"
    cov.parent.mkdir(parents=True, exist_ok=True)
    lock_path = str(cov) + ".lock"
    child = tmp_path / "try_lock.py"
    child.write_text(
        "import os, fcntl, sys\n"
        f"fd = os.open({lock_path!r}, os.O_WRONLY | os.O_CREAT, 0o600)\n"
        "try:\n"
        "    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
        "    sys.exit(0)\n"                       # acquired
        "except OSError:\n"
        "    sys.exit(3)\n"                       # blocked by the holder
    )
    with coverage_store_lock(cov):
        held = subprocess.run([sys.executable, str(child)])
        assert held.returncode == 3              # mutual exclusion across processes
    released = subprocess.run([sys.executable, str(child)])
    assert released.returncode == 0              # lock dropped on context exit
