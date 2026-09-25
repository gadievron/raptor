"""Tests for the external-scanner overlay views (per-scanner
intersection/residual + the analyzed-by-no-lane residual) — the
operator surfaces over the analyzed-units projection records.

View logic is unit-tested directly; two subprocess smokes confirm the
raptor-coverage-summary --scanners / --residual wiring.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from core.coverage.store_summary import (
    coverage_view,
    format_no_lane_residual,
    format_scanner_overlay,
    no_lane_residual,
    scanner_overlay_view,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-coverage-summary"

_CHECKLIST = {
    "files": [
        {"path": "src/a.c", "lines": 100, "items": [
            {"name": "f1", "line_start": 1, "line_end": 20,
             "kind": "function"},
            {"name": "f2", "line_start": 30, "line_end": 60,
             "kind": "function"},
            {"name": "f3", "line_start": 70, "line_end": 90,
             "kind": "function"},
        ]},
    ],
}


def _run_dir(tmp_path, overlay_rows=None, scanner_coverage=None,
             reviewed_rows=None):
    d = tmp_path / "scan-1"
    d.mkdir()
    (d / ".raptor-run.json").write_text("{}")
    (d / "checklist.json").write_text(json.dumps(_CHECKLIST))
    if overlay_rows is not None:
        sc = {"source": "results.json", "units_analyzed": len(overlay_rows),
              "units_matched": len(overlay_rows), "units_unmatched": 0,
              "units_error": 0, "join": "inventory", "model": "model-x",
              "level": "reachable"}
        sc.update(scanner_coverage or {})
        (d / "coverage-openant.json").write_text(json.dumps({
            "tool": "openant", "timestamp": "t",
            "functions_analysed": overlay_rows,
            "scanner_coverage": sc,
        }))
    if reviewed_rows is not None:
        (d / "coverage-audit.json").write_text(json.dumps({
            "tool": "audit", "timestamp": "t",
            "functions_analysed": reviewed_rows,
        }))
    return d


def _view_inputs(run_dir):
    return ([run_dir], _CHECKLIST, run_dir / "coverage.json",
            run_dir / "annotations")


def test_scanner_overlay_intersection_and_residual(tmp_path):
    d = _run_dir(
        tmp_path,
        overlay_rows=[{"file": "src/a.c", "function": "f1"},
                      {"file": "src/a.c", "function": "f2"}],
        reviewed_rows=[{"file": "src/a.c", "function": "f1"}],
    )
    rows = scanner_overlay_view(*_view_inputs(d))
    assert len(rows) == 1
    row = rows[0]
    assert row["tool"] == "openant"
    assert row["functions_analysed"] == 2
    # f1 has a review-grade audit mark: intersection 1, residual = f2.
    assert row["also_reviewed"] == 1
    assert row["unreviewed"] == [
        {"file": "src/a.c", "function": "f2", "line": 30}]
    assert row["units"]["units_analyzed"] == 2
    assert row["runs"][0]["model"] == "model-x"
    text = format_scanner_overlay(rows)
    assert "2 inventory function(s) analysed" in text
    assert "1 also LLM-reviewed" in text
    assert "src/a.c:f2 @ 30" in text
    assert "never review credit" in text


def test_scanner_overlay_skips_unresolvable_and_hostile_rows(tmp_path):
    d = _run_dir(
        tmp_path,
        overlay_rows=[
            {"file": "src/a.c", "function": "ghost"},   # not in inventory
            {"file": "src/a.c", "function": "f1"},
            "not-a-dict",
            {"file": 7, "function": "f2"},
        ],
        scanner_coverage={"units_analyzed": 4, "units_unmatched": 3,
                          "truncated": True},
    )
    rows = scanner_overlay_view(*_view_inputs(d))
    assert rows[0]["functions_analysed"] == 1
    text = format_scanner_overlay(rows)
    assert "3 unmatched" in text
    assert "TRUNCATED" in text


def test_scanner_overlay_defangs_artifact_derived_strings(tmp_path):
    d = _run_dir(
        tmp_path,
        overlay_rows=[{"file": "src/a.c", "function": "f1"}],
        scanner_coverage={"model": "evil\x1b]0;pwn\x07model"},
    )
    text = format_scanner_overlay(scanner_overlay_view(*_view_inputs(d)))
    assert "\x1b" not in text
    assert "evil" in text


def test_scanner_overlay_empty_states(tmp_path):
    d = _run_dir(tmp_path)  # no overlay record at all
    assert scanner_overlay_view(*_view_inputs(d)) == []
    assert "No external-scanner overlay records" in format_scanner_overlay([])
    assert scanner_overlay_view([d], None, None) is None
    assert "No coverage data" in format_scanner_overlay(None)


def test_no_lane_residual_lists_only_unexamined(tmp_path):
    d = _run_dir(
        tmp_path,
        overlay_rows=[{"file": "src/a.c", "function": "f1"}],
        reviewed_rows=[{"file": "src/a.c", "function": "f2"}],
    )
    view = coverage_view(*_view_inputs(d))
    residual = no_lane_residual(view)
    # f1 scanner-analysed, f2 reviewed -> only f3 has zero coverage.
    assert [(g["file"], g["function"]) for g in residual] == [
        ("src/a.c", "f3")]
    text = format_no_lane_residual(residual)
    assert "1 item(s) analysed by NO lane" in text
    assert "src/a.c:f3 @ 70" in text
    assert "Every checklist item has coverage" in format_no_lane_residual([])
    assert no_lane_residual(None) == []


_HANDLER_CHECKLIST = {
    "files": [
        {"path": "web/index.php", "lines": 60, "items": [
            {"name": "handler:top", "line_start": 1, "line_end": 40,
             "kind": "interstitial", "script_handler": True},
            {"name": "glue:includes", "line_start": 41, "line_end": 45,
             "kind": "interstitial", "script_handler": False},
            {"name": "helper", "line_start": 50, "line_end": 60,
             "kind": "function"},
        ]},
    ],
}


def _handler_run_dir(tmp_path):
    d = tmp_path / "scan-h"
    d.mkdir()
    (d / ".raptor-run.json").write_text("{}")
    (d / "checklist.json").write_text(json.dumps(_HANDLER_CHECKLIST))
    return d


def test_handler_spans_are_no_lane_residual_items(tmp_path):
    # A stamped script-handler span is a reviewable unit: with zero
    # coverage of any grade it belongs in the no-lane residual, exactly
    # like a function. Plain interstitial glue stays excluded.
    d = _handler_run_dir(tmp_path)
    view = coverage_view([d], _HANDLER_CHECKLIST, d / "cov-a.json", None)
    residual = no_lane_residual(view)
    assert [(g["file"], g["function"]) for g in residual] == [
        ("web/index.php", "handler:top"), ("web/index.php", "helper")]
    text = format_no_lane_residual(residual)
    assert "web/index.php:handler:top @ 1" in text


def test_handler_span_scanner_grade_is_extent_not_review(tmp_path):
    # Scanner-grade coverage takes the handler span out of the no-lane
    # residual (it has coverage) but never out of the scanner-only set:
    # it shows as analysed-but-unreviewed until a review-grade llm mark
    # lands, at which point it joins the intersection.
    d = _handler_run_dir(tmp_path)
    (d / "coverage-openant.json").write_text(json.dumps({
        "tool": "openant", "timestamp": "t",
        "functions_analysed": [
            {"file": "web/index.php", "function": "handler:top"}],
        "scanner_coverage": {"join": "inventory", "units_analyzed": 1,
                             "units_matched": 1, "units_unmatched": 0,
                             "units_error": 0},
    }))
    view = coverage_view([d], _HANDLER_CHECKLIST, d / "cov-b.json", None)
    assert [g["function"] for g in no_lane_residual(view)] == ["helper"]
    rows = scanner_overlay_view([d], _HANDLER_CHECKLIST,
                                d / "cov-c.json", None)
    assert rows[0]["functions_analysed"] == 1
    assert rows[0]["also_reviewed"] == 0
    assert rows[0]["unreviewed"] == [
        {"file": "web/index.php", "function": "handler:top", "line": 1}]
    # A review-grade llm mark on the span moves it into the
    # intersection — the reviewed set walks the full item inventory.
    (d / "coverage-audit.json").write_text(json.dumps({
        "tool": "audit", "timestamp": "t",
        "functions_analysed": [
            {"file": "web/index.php", "function": "handler:top"}],
    }))
    rows2 = scanner_overlay_view([d], _HANDLER_CHECKLIST,
                                 d / "cov-d.json", None)
    assert rows2[0]["also_reviewed"] == 1
    assert rows2[0]["unreviewed"] == []


def test_deferred_record_refused_against_foreign_inventory(tmp_path):
    d = _run_dir(tmp_path)
    (d / "coverage-openant.json").write_text(json.dumps({
        "tool": "openant", "timestamp": "t",
        "functions_analysed": [{"file": "src/a.c", "function": "f1"}],
        "scanner_coverage": {"join": "deferred", "units_analyzed": 1,
                             "target_path": "/some/other/tree"},
    }))
    checklist = dict(_CHECKLIST, target_path="/this/tree")
    rows = scanner_overlay_view([d], checklist, d / "coverage.json",
                                d / "annotations")
    row = rows[0]
    # The join is refused (wrong tree), the record stays visible.
    assert row["functions_analysed"] == 0
    assert row["runs"][0]["join"] == "deferred-refused"
    assert row["units"]["units_analyzed"] == 1
    text = format_scanner_overlay(rows)
    assert "deferred-refused" in text
    # ...and a MATCHING target joins.
    (d / "coverage-openant.json").write_text(json.dumps({
        "tool": "openant", "timestamp": "t",
        "functions_analysed": [{"file": "src/a.c", "function": "f1"}],
        "scanner_coverage": {"join": "deferred", "units_analyzed": 1,
                             "target_path": "/this/tree"},
    }))
    rows2 = scanner_overlay_view([d], checklist, d / "cov2.json",
                                 d / "annotations")
    assert rows2[0]["functions_analysed"] == 1


def test_multi_record_sums_state_their_scope(tmp_path):
    d1 = _run_dir(tmp_path,
                  overlay_rows=[{"file": "src/a.c", "function": "f1"}])
    d2 = tmp_path / "scan-2"
    d2.mkdir()
    (d2 / ".raptor-run.json").write_text("{}")
    (d2 / "coverage-openant.json").write_text(json.dumps({
        "tool": "openant", "timestamp": "t",
        "functions_analysed": [{"file": "src/a.c", "function": "f2"}],
        "scanner_coverage": {"join": "inventory", "units_analyzed": 3,
                             "units_matched": 3, "units_unmatched": 0,
                             "units_error": 0},
    }))
    rows = scanner_overlay_view([d1, d2], _CHECKLIST,
                                tmp_path / "cov.json", None)
    row = rows[0]
    assert row["units"]["units_analyzed"] == 4  # 1 + 3, summed
    text = format_scanner_overlay(rows)
    assert "4 analysed" in text
    assert "(summed across 2 records)" in text


# ------------------------------------------------------------- CLI smoke


def _run_cli(*args):
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    env["RAPTOR_DIR"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        env=env, capture_output=True, text=True,
    )


def test_cli_scanners_view(tmp_path):
    d = _run_dir(tmp_path,
                 overlay_rows=[{"file": "src/a.c", "function": "f1"}])
    r = _run_cli(str(d), "--scanners")
    assert r.returncode == 0, r.stderr
    assert "External-scanner coverage overlay" in r.stdout
    assert "openant" in r.stdout


def test_cli_project_scan_retroactive(tmp_path):
    # A run whose scan artifacts exist but whose overlay record does
    # not (a pre-overlay or failed run): --project-scan projects it.
    run = tmp_path / "run1"
    run.mkdir()
    (run / ".raptor-run.json").write_text(
        json.dumps({"target_path": "/t", "command": "openant"}))
    (run / "checklist.json").write_text(json.dumps(_CHECKLIST))
    scan = run / "openant_scan"
    scan.mkdir()
    (scan / "results.json").write_text(json.dumps({
        "model": "m", "results": [
            {"unit_id": "src/a.c:f1", "finding": "safe"}]}))
    r = _run_cli("--project-scan", str(scan))
    assert r.returncode == 0, r.stderr
    assert "coverage overlay" in r.stdout
    assert (run / "coverage-openant.json").exists()

    r2 = _run_cli("--project-scan", str(tmp_path / "missing"))
    assert r2.returncode == 1
    assert "scan dir not found" in r2.stderr


def test_cli_residual_view(tmp_path):
    d = _run_dir(tmp_path,
                 overlay_rows=[{"file": "src/a.c", "function": "f1"}])
    r = _run_cli(str(d), "--residual")
    assert r.returncode == 0, r.stderr
    assert "analysed by NO lane" in r.stdout
    assert "src/a.c:f2" in r.stdout
    assert "src/a.c:f3" in r.stdout
    # f1 was scanner-analysed — out of the no-lane residual.
    assert "src/a.c:f1" not in r.stdout
