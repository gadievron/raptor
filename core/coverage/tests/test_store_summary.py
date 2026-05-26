"""Tests for the store-backed coverage view (category/depth + gaps)."""

from __future__ import annotations

from core.coverage.store import CoverageStore
from core.coverage.store_summary import format_store_view, store_view

_CHECKLIST = {
    "files": [
        {"path": "a.c", "total_lines": 100, "items": [
            {"name": "f1", "line_start": 0, "line_end": 20},
            {"name": "f2", "line_start": 30, "line_end": 60},
        ]},
        {"path": "b.c", "total_lines": 50, "functions": [
            {"name": "g1", "line_start": 0, "line_end": 10},
        ]},
    ],
}


def _store(tmp_path):
    return CoverageStore(tmp_path / "coverage.json", target="zip:abc")


def test_store_view_category_breakdown_and_gaps(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 20, "semgrep")          # f1: static
    s.mark("a.c", 30, 60, "claude:audit")    # f2: llm
    # b.c/g1: nothing.
    v = store_view(s, _CHECKLIST)

    assert v["total_functions"] == 3
    assert v["functions_covered"] == 2       # f1, f2
    assert v["functions_by_category"] == {"static": 1, "llm": 1, "runtime": 0}
    assert v["gap_no_tool"] == 1             # g1
    assert v["gap_no_llm"] == 2              # f1 (static only) + g1
    gap_keys = {(g["file"], g["function"]) for g in v["llm_gap_functions"]}
    assert gap_keys == {("a.c", "f1"), ("b.c", "g1")}


def test_store_view_counts_a_function_once_per_category(tmp_path):
    s = _store(tmp_path)
    # f2 covered by two llm tools -> still counts once for llm.
    s.mark("a.c", 30, 60, "claude:audit")
    s.mark("a.c", 30, 60, "validate:stage-a")
    v = store_view(s, _CHECKLIST)
    assert v["functions_by_category"]["llm"] == 1


def test_store_view_verdict_buckets_and_review_gap(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 20, "semgrep")                       # f1 clean
    s.mark("a.c", 30, 60, "semgrep")
    s.link_finding("a.c", "F1", line=42, retained=False)  # f2 found_then_lost
    # b.c/g1 unexamined
    v = store_view(s, _CHECKLIST)
    assert v["verdicts"] == {
        "clean": 1, "open": 0, "found_then_lost": 1, "unexamined": 1,
    }
    review = {(g["function"], g["verdict"]) for g in v["review_gap"]}
    assert review == {("f2", "found_then_lost"), ("g1", "unexamined")}


def test_store_view_counts_interstitial_by_kind_and_surfaces_gap(tmp_path):
    # Interstitial items must be counted as their own kind (not "functions")
    # and must show up in the review gap when unexamined — that's the point.
    s = _store(tmp_path)
    checklist = {"files": [
        {"path": "a.c", "lines": 100, "items": [
            {"name": "f1", "kind": "function", "line_start": 1, "line_end": 20},
            {"name": "interstitial:30-35", "kind": "interstitial",
             "line_start": 30, "line_end": 35},
        ]},
    ]}
    s.mark("a.c", 1, 20, "semgrep")          # f1 examined; interstitial not
    v = store_view(s, checklist)
    # counted for completeness...
    assert v["items_by_kind"] == {"function": 1, "interstitial": 1}
    assert v["total_functions"] == 2         # all items
    assert v["verdicts"]["unexamined"] == 1  # the interstitial is unexamined
    # ...but kept OUT of the actionable gap listings (it's non-function glue)
    review_names = {g["function"] for g in v["review_gap"]}
    assert "interstitial:30-35" not in review_names
    llm_names = {g["function"] for g in v["llm_gap_functions"]}
    assert "interstitial:30-35" not in llm_names

    out = format_store_view(v)
    assert "Items: 2 total" in out
    assert "function 1" in out and "interstitial 1" in out


def test_render_run_coverage_store_view(tmp_path):
    import json

    from core.coverage.store_summary import render_run_coverage

    run = tmp_path / "agentic-1"
    (run / "scan").mkdir(parents=True)
    (run / "checklist.json").write_text(json.dumps({"files": [
        {"path": "a.c", "lines": 50, "items": [
            {"name": "f1", "line_start": 1, "line_end": 20}]}]}))
    (run / "scan" / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
    out = render_run_coverage(run)
    assert "Coverage (persistent store)" in out
    assert "static" in out


def test_render_run_coverage_file_level_when_no_checklist(tmp_path):
    import json

    from core.coverage.store_summary import render_run_coverage

    run = tmp_path / "scan-1"
    run.mkdir()
    (run / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": ["/abs/a.py"],
         "version": "1.79.0", "timestamp": "t"}))
    out = render_run_coverage(run)
    assert "file-level — no function inventory" in out


def test_render_run_coverage_none_when_empty(tmp_path):
    from core.coverage.store_summary import render_run_coverage

    run = tmp_path / "empty"
    run.mkdir()
    assert render_run_coverage(run) is None


def test_file_level_view_without_inventory(tmp_path):
    import json

    from core.coverage.store_summary import file_level_view, format_file_level_view

    run = tmp_path / "scan-1"
    run.mkdir()
    (run / "coverage-semgrep.json").write_text(json.dumps({
        "tool": "semgrep", "files_examined": ["/abs/a.py", "/abs/b.py"],
        "version": "1.79.0", "rules_applied": ["all"],
        "timestamp": "2026-05-26T10:00:00Z"}))
    (run / ".raptor-run.json").write_text(json.dumps({
        "command": "scan", "status": "completed",
        "timestamp": "2026-05-26T09:59:00Z",
        "manifest": {"target": {"source": "directory"}}}))

    v = file_level_view([run])
    assert v["tools"]["semgrep"]["files"] == ["/abs/a.py", "/abs/b.py"]
    assert v["tools"]["semgrep"]["versions"] == ["1.79.0"]
    assert v["runs"][0]["command"] == "scan" and v["runs"][0]["status"] == "completed"

    out = format_file_level_view(v)
    assert "file-level — no function inventory" in out
    assert "semgrep 1.79.0: 2 file(s) examined" in out
    assert "scan / completed" in out


def test_open_finding_without_coverage_counts_as_examined(tmp_path):
    # A finding with no coverage record (the agentic case before coverage
    # records are wired): the function reads 'open' and must count as examined,
    # NOT under "no tool at all" — the two sections must agree.
    s = _store(tmp_path)
    s.link_finding("a.c", "F1", line=42, retained=True)   # f2 (30-60), no mark()
    v = store_view(s, _CHECKLIST)
    assert v["verdicts"]["open"] == 1
    assert v["functions_covered"] == 1                    # the open-finding fn
    assert v["gap_no_tool"] == 2                          # f1 + g1 (truly unexamined)
    assert v["functions_by_category"] == {"static": 0, "llm": 0, "runtime": 0}


def test_store_view_surfaces_provenance(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 20, "semgrep")
    s.stamp_coverage("a.c", "semgrep", version="1.67.0",
                     timestamp="2026-05-26T10:00:00Z")
    s.mark("a.c", 30, 60, "llm")
    s.stamp_coverage("a.c", "llm", models=["gemini-2.5-pro-002"],
                     timestamp="2026-05-26T11:00:00Z")
    v = store_view(s, _CHECKLIST)
    assert v["provenance"]["tools"]["semgrep"] == ["1.67.0"]
    assert v["provenance"]["models"] == ["gemini-2.5-pro-002"]
    assert v["provenance"]["newest"] == "2026-05-26T11:00:00Z"

    out = format_store_view(v)
    assert "Provenance:" in out
    assert "semgrep: 1.67.0" in out
    assert "llm models: gemini-2.5-pro-002" in out


def test_format_store_view_renders(tmp_path):
    s = _store(tmp_path)
    s.mark("a.c", 0, 20, "semgrep")
    s.mark("a.c", 30, 60, "semgrep")
    s.link_finding("a.c", "F1", line=42, retained=False)  # found_then_lost
    out = format_store_view(store_view(s, _CHECKLIST))
    assert "Coverage (persistent store)" in out
    assert "zip:abc" in out
    assert "no LLM review:" in out
    assert "found-then-lost:" in out
    assert "Found-then-lost — detail discarded, re-examine" in out
    assert "a.c:f2" in out
    # No red/green indicators (output-style rule).
    assert "🔴" not in out and "🟢" not in out
