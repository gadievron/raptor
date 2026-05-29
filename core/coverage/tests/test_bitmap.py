"""Bitmap fallback: a (file, tool) with many sparse intervals switches to a
line-set in memory, with identical query semantics and an interval on-disk form.
"""

from __future__ import annotations

import json

from core.coverage.store import CoverageStore, _BITMAP_THRESHOLD


def _store(tmp_path):
    return CoverageStore(tmp_path / "coverage.json", target="zip:x")


def _sparse_lines(n):
    """n disjoint single lines (1, 3, 5, …) → n intervals before coalescing."""
    return list(range(1, 1 + 2 * n, 2))


def test_converts_to_bitmap_above_threshold(tmp_path):
    s = _store(tmp_path)
    lines = _sparse_lines(_BITMAP_THRESHOLD + 11)
    for ln in lines:
        s.mark("a.c", ln, ln, "gcov")
    # Internal representation switched to a set once it crossed the threshold.
    assert isinstance(s._files["a.c"]["tools"]["gcov"], set)
    # Query semantics identical to the interval backend.
    assert s.who_checked("a.c", lines[0]) == ["gcov"]
    assert s.who_checked("a.c", lines[-1]) == ["gcov"]
    assert s.who_checked("a.c", lines[0] + 1) == []          # gap line
    assert s.tool_coverage_of_range("a.c", 1, 10) == {"gcov": 5}  # 1,3,5,7,9


def test_stays_intervals_below_threshold(tmp_path):
    s = _store(tmp_path)
    for ln in _sparse_lines(_BITMAP_THRESHOLD - 1):
        s.mark("a.c", ln, ln, "gcov")
    assert isinstance(s._files["a.c"]["tools"]["gcov"], list)


def test_bitmap_delta_accounting(tmp_path):
    s = _store(tmp_path)
    for ln in _sparse_lines(_BITMAP_THRESHOLD + 11):
        s.mark("a.c", ln, ln, "gcov")
    assert s.mark("a.c", 1, 1, "gcov") == 0      # already covered (odd line)
    assert s.mark("a.c", 2, 2, "gcov") == 1      # new (even line)
    # 2,3,4,5,6: 2 (just added), 3, 5 covered → only 4 and 6 are new.
    assert s.mark("a.c", 2, 6, "gcov") == 2


def test_bitmap_roundtrips_as_intervals_on_disk(tmp_path):
    s = _store(tmp_path)
    for ln in _sparse_lines(_BITMAP_THRESHOLD + 11):
        s.mark("a.c", ln, ln, "gcov")
    s.set_file_meta("a.c", total_lines=400)
    cov_before = s.file_coverage("a.c")
    covered_before = s.covered_lines("a.c")
    p = s.save()

    disk = json.loads(p.read_text())
    ivs = disk["files"]["a.c"]["tools"]["gcov"]
    assert isinstance(ivs, list)
    assert all(isinstance(x, list) and len(x) == 2 for x in ivs)

    reloaded = CoverageStore(p)
    # Comes back as intervals (disk form); queries match the pre-save store.
    assert isinstance(reloaded._files["a.c"]["tools"]["gcov"], list)
    assert reloaded.file_coverage("a.c") == cov_before
    assert reloaded.covered_lines("a.c") == covered_before


def test_bitmap_and_interval_tools_coexist(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 1, 400, "semgrep")             # whole file: one interval
    for ln in _sparse_lines(_BITMAP_THRESHOLD + 11):
        s.mark("a.c", ln, ln, "gcov")            # sparse: becomes a set
    assert isinstance(s._files["a.c"]["tools"]["semgrep"], list)
    assert isinstance(s._files["a.c"]["tools"]["gcov"], set)
    # Union spans the whole file via semgrep; per-line membership is per-tool.
    assert s.covered_lines("a.c") == [[1, 400]]
    assert s.who_checked("a.c", 3) == ["gcov", "semgrep"]
    assert s.who_checked("a.c", 2) == ["semgrep"]   # gcov skipped even lines


def test_bitmap_matches_interval_semantics_for_function_queries(tmp_path):
    # function_verdict / function_covered work the same over a bitmap-backed
    # tool as over intervals.
    s = _store(tmp_path)
    for ln in _sparse_lines(_BITMAP_THRESHOLD + 11):
        s.mark("a.c", ln, ln, "gcov")
    assert s.function_covered("a.c", 1, 9, category="runtime") is True
    assert s.function_covered("a.c", 2, 2, category="runtime") is False
    # [1,9] = 9 lines; odd lines 1,3,5,7,9 covered = 5/9 ≈ 56%.
    assert s.who_checked_function("a.c", 1, 9) == {"gcov": "partial (56%)"}
