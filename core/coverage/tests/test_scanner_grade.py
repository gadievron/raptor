"""Consumer trace for the ``openant`` scanner coverage grade.

The analyzed-units overlay records what an EXTERNAL scanner analysed
as ``tool="openant"`` coverage. The whole contract of that grade is
one-directional: it may add examination EXTENT (the function was
looked at by an llm-category tool) but must never satisfy any
review-covered set anywhere. These tests walk every consumer that
grants review credit from coverage state and prove the scanner grade
is structurally outside each one:

  * the registry classification itself (llm category, scanned depth),
  * ``store_summary.store_view`` (functions_reviewed / llm gap),
  * ``store_summary.file_breakdown`` (per-file llm-reviewed column),
  * ``store_summary.store_llm_coverage_percent`` (--fail-under gate),
  * the audit gap fold (``core.audit.gaps._build_covered_set``),
  * the record importer (marks land under the scanner label, so every
    depth-aware screen above applies to imported records too).
"""

from __future__ import annotations

from core.coverage.registry import classify
from core.coverage.store import CoverageStore
from core.coverage.store_summary import (
    file_breakdown,
    store_llm_coverage_percent,
    store_view,
)

_CHECKLIST = {
    "files": [
        {"path": "src/a.c", "lines": 100, "items": [
            {"name": "f1", "line_start": 1, "line_end": 20,
             "kind": "function"},
            {"name": "f2", "line_start": 30, "line_end": 60,
             "kind": "function"},
        ]},
    ],
}


def _store(tmp_path):
    return CoverageStore(tmp_path / "coverage.json", target="zip:abc")


def test_openant_classifies_as_llm_scanned():
    # Scanner grade: llm category (extent views attribute it), scanned
    # depth (identical to the unknown-tool default — a registry
    # regression can never promote it to review credit).
    assert classify("openant") == ("llm", "scanned")
    assert classify("openant:levelled") == ("llm", "scanned")


def test_openant_marks_never_count_as_reviewed_in_store_view(tmp_path):
    s = _store(tmp_path)
    s.mark("src/a.c", 1, 20, "openant")
    v = store_view(s, _CHECKLIST)
    # Extent: the llm category attributes the scanner's examination.
    assert v["functions_by_category"]["llm"] == 1
    # Review: NOT reviewed — f1 stays in the LLM-review gap.
    assert v["functions_reviewed"] == 0
    gap = {(g["file"], g["function"]) for g in v["llm_gap_functions"]}
    assert ("src/a.c", "f1") in gap
    assert ("src/a.c", "f2") in gap


def test_openant_marks_never_move_the_fail_under_percent(tmp_path):
    s = _store(tmp_path)
    baseline = store_llm_coverage_percent(store_view(s, _CHECKLIST))
    s.mark("src/a.c", 1, 20, "openant")
    s.mark("src/a.c", 30, 60, "openant")
    assert store_llm_coverage_percent(store_view(s, _CHECKLIST)) == baseline


def test_openant_marks_never_count_in_file_breakdown_llm_column(tmp_path):
    s = _store(tmp_path)
    s.mark("src/a.c", 1, 20, "openant")
    rows = file_breakdown(s, _CHECKLIST)
    row = next(r for r in rows if r["path"] == "src/a.c")
    assert row["llm"] == 0
    # ... while examined-extent honestly counts the scanner's look.
    assert row["examined"] == 1


def test_review_grade_control_still_reviews(tmp_path):
    # Control for the three screens above: an actual review-grade mark
    # DOES flip them — proving the openant assertions test the depth
    # screen, not a broken fixture.
    s = _store(tmp_path)
    s.mark("src/a.c", 1, 20, "audit")
    v = store_view(s, _CHECKLIST)
    assert v["functions_reviewed"] == 1
    assert ("src/a.c", "f1") not in {
        (g["file"], g["function"]) for g in v["llm_gap_functions"]}


def test_audit_gap_fold_ignores_openant_functions_analysed():
    # core.audit.gaps._build_covered_set is the gap-SUPPRESSION seam:
    # a functions_analysed row only earns a covered key at
    # (llm, analysed). The scanner record must contribute nothing —
    # otherwise the /audit and --gap-audit residual would silently
    # retire functions only an external scanner ever looked at.
    from core.audit.gaps import _build_covered_set

    scanner_record = {
        "tool": "openant",
        "functions_analysed": [{"file": "src/a.c", "function": "f1"}],
    }
    assert _build_covered_set([scanner_record]) == set()
    # Control: the same row under a review-grade tool DOES cover.
    review_record = dict(scanner_record, tool="audit")
    assert _build_covered_set([review_record]) != set()


def test_imported_openant_record_marks_scanner_label_only(tmp_path):
    # End-to-end through the importer: a coverage-openant.json record's
    # functions_analysed lands as marks under the "openant" label, so
    # every depth-aware review screen (tested above) applies to the
    # imported state too — and the residual/extent views see it.
    from core.coverage.importer import (
        _function_ranges,
        _inventory_paths,
        import_functions_analysed,
    )

    s = _store(tmp_path)
    record = {
        "tool": "openant",
        "functions_analysed": [{"file": "src/a.c", "function": "f1"}],
    }
    marked = import_functions_analysed(
        s, record, _function_ranges(_CHECKLIST),
        _inventory_paths(_CHECKLIST))
    assert marked == 1
    assert "openant" in s.tool_coverage_of_range("src/a.c", 1, 20)
    v = store_view(s, _CHECKLIST)
    assert v["functions_reviewed"] == 0
    # f1 leaves the no-lane residual (it was examined by SOME tool)...
    residual = {(g["file"], g["function"])
                for g in v["review_gap"] if g["verdict"] == "unexamined"}
    assert ("src/a.c", "f1") not in residual
    # ...but f2 (no unit analysed) stays in it.
    assert ("src/a.c", "f2") in residual
