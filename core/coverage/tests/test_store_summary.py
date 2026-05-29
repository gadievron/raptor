"""Tests for the store-backed coverage view (category/depth + gaps)."""

from __future__ import annotations

from core.coverage.store import CoverageStore
from core.coverage.store_summary import format_store_view, store_view

_CHECKLIST = {
    "files": [
        {"path": "a.c", "lines": 100, "items": [
            {"name": "f1", "line_start": 0, "line_end": 20},
            {"name": "f2", "line_start": 30, "line_end": 60},
        ]},
        {"path": "b.c", "lines": 50, "functions": [
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


_MIXED_KINDS = {"files": [{"path": "a.c", "lines": 50, "items": [
    {"name": "fn", "kind": "function", "line_start": 1, "line_end": 10},
    {"name": "tl", "kind": "top_level", "line_start": 12, "line_end": 12},
    {"name": "G", "kind": "global", "line_start": 20, "line_end": 20},
    {"name": "M", "kind": "macro", "line_start": 25, "line_end": 25},
    {"name": "T", "kind": "class", "line_start": 30, "line_end": 35},
]}]}


def test_llm_gap_lists_only_reviewable_kinds(tmp_path):
    # No llm coverage anywhere: only function + top_level are the LLM-review
    # gap; globals/macros/typedefs are excluded by kind.
    s = _store(tmp_path)
    s.import_inventory_meta(_MIXED_KINDS)
    view = store_view(s, _MIXED_KINDS)
    assert {g["function"] for g in view["llm_gap_functions"]} == {"fn", "tl"}
    assert view["llm_reviewable"] == 2
    assert view["gap_no_llm"] == 2
    # Completeness counts still include every kind.
    assert view["total_functions"] == 5


def test_llm_gap_excludes_reviewed_function(tmp_path):
    s = _store(tmp_path)
    s.import_inventory_meta(_MIXED_KINDS)
    s.mark("a.c", 1, 10, "claude:audit")       # llm reviews fn (analysed depth)
    view = store_view(s, _MIXED_KINDS)
    assert {g["function"] for g in view["llm_gap_functions"]} == {"tl"}
    assert view["llm_reviewable"] == 2
    assert view["functions_reviewed"] == 1


def test_whole_file_read_is_not_reviewed(tmp_path):
    # A whole-file `read` mark (llm category, scanned depth) is NOT a review —
    # the functions stay in the LLM-review gap. This is the read-vs-reviewed
    # distinction /audit depends on.
    s = _store(tmp_path)
    s.import_inventory_meta(_MIXED_KINDS)
    s.mark("a.c", 1, 50, "read")               # the LLM only READ the file
    view = store_view(s, _MIXED_KINDS)
    assert view["functions_reviewed"] == 0
    assert {g["function"] for g in view["llm_gap_functions"]} == {"fn", "tl"}
    # ...but it does count as llm *extent* (the LLM did touch it).
    assert view["functions_by_category"]["llm"] >= 1


def test_store_threshold_helpers(tmp_path):
    from core.coverage.store_summary import (
        format_store_threshold_result,
        store_coverage_threshold_met,
        store_llm_coverage_percent,
    )
    s = _store(tmp_path)
    s.import_inventory_meta(_MIXED_KINDS)
    s.mark("a.c", 1, 10, "claude:audit")       # 1 of 2 reviewable → 50%
    view = store_view(s, _MIXED_KINDS)
    assert store_llm_coverage_percent(view) == 50.0
    assert store_coverage_threshold_met(view, 50.0)
    assert not store_coverage_threshold_met(view, 75.0)
    result = format_store_threshold_result(view, 75.0)
    assert "50.0% LLM item coverage" in result
    assert "FAIL" in result


def test_store_threshold_no_reviewable_is_100(tmp_path):
    from core.coverage.store_summary import store_llm_coverage_percent
    s = _store(tmp_path)
    only_global = {"files": [{"path": "a.c", "lines": 5, "items": [
        {"name": "G", "kind": "global", "line_start": 1, "line_end": 1}]}]}
    s.import_inventory_meta(only_global)
    assert store_llm_coverage_percent(store_view(s, only_global)) == 100.0


def test_render_coverage_combines_state_and_execution(tmp_path):
    import json
    from core.coverage.store_summary import render_coverage
    run = tmp_path / "run"
    run.mkdir()
    (run / "coverage-semgrep.json").write_text(json.dumps({
        "tool": "semgrep", "files_examined": ["a.c"],
        "rules_applied": ["crypto"], "version": "1.5", "timestamp": "t"}))
    report = render_coverage([run], _CHECKLIST, run / "coverage.json")
    assert "Coverage (persistent store)" in report     # store-state section
    assert "Tool execution" in report                  # execution-detail section
    assert "semgrep" in report


def test_render_coverage_file_level_without_checklist(tmp_path):
    import json
    from core.coverage.store_summary import render_coverage
    run = tmp_path / "run"
    run.mkdir()
    (run / ".raptor-run.json").write_text("{}")
    (run / "coverage-semgrep.json").write_text(json.dumps({
        "tool": "semgrep", "files_examined": ["x.c"], "timestamp": "t"}))
    report = render_coverage([run], None, run / "coverage.json")
    assert report is not None and "file-level" in report


def test_coverage_view_none_without_checklist(tmp_path):
    from core.coverage.store_summary import coverage_view
    assert coverage_view([tmp_path], None, tmp_path / "coverage.json") is None


def test_file_breakdown_counts_and_worst_first(tmp_path):
    from core.coverage.store_summary import file_breakdown
    s = _store(tmp_path)
    s.import_inventory_meta(_CHECKLIST)
    s.mark("a.c", 0, 20, "claude:audit")       # f1 llm-reviewed
    s.link_finding("a.c", "F1", line=40)       # finding in f2
    rows = file_breakdown(s, _CHECKLIST)
    by_path = {r["path"]: r for r in rows}
    assert by_path["a.c"]["items"] == 2
    assert by_path["a.c"]["reviewable"] == 2
    assert by_path["a.c"]["llm"] == 1
    assert by_path["a.c"]["findings"] == 1
    # b.c has no llm coverage (ratio 0) → sorts before a.c (ratio 0.5).
    assert rows[0]["path"] == "b.c"


def test_format_file_breakdown_table(tmp_path):
    from core.coverage.store_summary import file_breakdown, format_file_breakdown
    s = _store(tmp_path)
    s.import_inventory_meta(_CHECKLIST)
    table = format_file_breakdown(file_breakdown(s, _CHECKLIST))
    assert "Per-file" in table
    assert "a.c" in table and "b.c" in table
    assert format_file_breakdown([]) == ""


def test_render_coverage_detailed_includes_per_file_table(tmp_path):
    import json
    from core.coverage.store_summary import render_coverage
    run = tmp_path / "run"
    run.mkdir()
    (run / "coverage-semgrep.json").write_text(json.dumps(
        {"tool": "semgrep", "files_examined": ["a.c"], "timestamp": "t"}))
    report = render_coverage([run], _CHECKLIST, run / "coverage.json", detailed=True)
    assert "Per-file" in report
    # Non-detailed omits the table.
    plain = render_coverage([run], _CHECKLIST, run / "coverage.json")
    assert "Per-file" not in plain
