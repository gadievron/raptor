#!/usr/bin/env python3
"""Tests for the blamed-line execution check."""

import json
from unittest.mock import patch

import packages.binary_analysis.blamed_lines as bl
from packages.binary_analysis.blamed_lines import (
    BlamedLineResult,
    check_blamed_lines,
    check_report,
    extract_blamed_lines,
    render_section,
)

REPORT = """# Root cause

### Step 1: Allocation
**Location:** `src/parser.c:120`

### Step 2: Overwrite
**Location:** `src/parser.c:207`

### Step 3: Crash (repeat of step 1 file)
**Location:** `src/parser.c:120`

### Step 4: Helper
**Location:** `lib/util.c:33`
"""


class TestExtraction:
    def test_extracts_dedup_preserves_order(self):
        assert extract_blamed_lines(REPORT) == [
            ("src/parser.c", 120),
            ("src/parser.c", 207),
            ("lib/util.c", 33),
        ]

    def test_unsafe_paths_dropped(self):
        text = (
            "**Location:** `../../etc/passwd:1`\n"
            "**Location:** `-flag.c:2`\n"
            "**Location:** `ok.c:3`\n"
        )
        assert extract_blamed_lines(text) == [("ok.c", 3)]

    def test_cap_applies(self):
        text = "\n".join(
            f"**Location:** `f{i}.c:{i + 1}`" for i in range(200))
        assert len(extract_blamed_lines(text)) == bl._MAX_BLAMED_LINES

    def test_prose_file_line_refs_ignored(self):
        # Only the Location anchor counts — evidence prose mentioning
        # file:line must not be blamed.
        assert extract_blamed_lines("see parser.c:99 in the trace") == []


class TestCheckBlamedLines:
    def test_no_coverage_data_all_unknown(self, tmp_path):
        results = check_blamed_lines([("a.c", 1)], tmp_path)
        assert results[0].status == "unknown"
        assert "no coverage data" in results[0].reason

    def _coverage_dir(self, tmp_path):
        (tmp_path / "a.c.gcov").write_text("", encoding="utf-8")
        return tmp_path

    def test_checker_unavailable_unknown(self, tmp_path):
        cov = self._coverage_dir(tmp_path)
        with patch.object(bl, "_resolve_checker", return_value=None):
            results = check_blamed_lines([("a.c", 1)], cov)
        assert results[0].status == "unknown"
        assert "unavailable" in results[0].reason

    def _fake_proc(self, returncode=0, stdout="", stderr=""):
        class _P:
            pass
        p = _P()
        p.returncode = returncode
        p.stdout = stdout
        p.stderr = stderr
        return p

    def test_parses_executed_and_not_executed(self, tmp_path):
        cov = self._coverage_dir(tmp_path)
        fake = self._fake_proc(returncode=1, stdout=(
            "a.c:1 EXECUTED (5 times)\n"
            "a.c:2 NOT EXECUTED\n"
            "a.c:3 EXECUTED (1 time)\n"
        ))
        with patch.object(bl, "_resolve_checker",
                          return_value=cov / "line-checker"), \
             patch.object(bl.subprocess, "run", return_value=fake):
            results = check_blamed_lines(
                [("a.c", 1), ("a.c", 2), ("a.c", 3)], cov)
        assert [r.status for r in results] == [
            "executed", "not_executed", "executed"]
        assert results[0].count == 5

    def test_exit_2_marks_file_unknown(self, tmp_path):
        cov = self._coverage_dir(tmp_path)
        fake = self._fake_proc(
            returncode=2, stderr="Error: No coverage data for b.c")
        with patch.object(bl, "_resolve_checker",
                          return_value=cov / "line-checker"), \
             patch.object(bl.subprocess, "run", return_value=fake):
            results = check_blamed_lines([("b.c", 9)], cov)
        assert results[0].status == "unknown"
        assert "No coverage data" in results[0].reason

    def test_missing_output_line_unknown(self, tmp_path):
        cov = self._coverage_dir(tmp_path)
        fake = self._fake_proc(returncode=0, stdout="a.c:1 EXECUTED (2 times)\n")
        with patch.object(bl, "_resolve_checker",
                          return_value=cov / "line-checker"), \
             patch.object(bl.subprocess, "run", return_value=fake):
            results = check_blamed_lines([("a.c", 1), ("a.c", 7)], cov)
        assert results[1].status == "unknown"


class TestRenderAndStamp:
    def test_not_executed_prominent(self):
        section = render_section([
            BlamedLineResult("a.c", 1, "executed", count=2),
            BlamedLineResult("a.c", 2, "not_executed"),
        ])
        assert "NOT EXECUTED" in section
        assert "strong signal" in section

    def test_check_report_stamps_and_sidecars(self, tmp_path):
        report = tmp_path / "root-cause-hypothesis-1.md"
        report.write_text(REPORT, encoding="utf-8")
        fake_results = [BlamedLineResult("src/parser.c", 120, "not_executed")]
        with patch.object(bl, "check_blamed_lines",
                          return_value=fake_results):
            summary = check_report(report, tmp_path)
        assert summary["not_executed"] == 1
        text = report.read_text()
        assert bl._SECTION_MARKER in text
        sidecar = json.loads(
            (tmp_path / "root-cause-hypothesis-1.md.line-check.json")
            .read_text())
        assert sidecar["results"][0]["status"] == "not_executed"

    def test_stamp_idempotent(self, tmp_path):
        report = tmp_path / "root-cause-hypothesis-1.md"
        report.write_text(REPORT, encoding="utf-8")
        fake_results = [BlamedLineResult("src/parser.c", 120, "executed",
                                         count=1)]
        with patch.object(bl, "check_blamed_lines",
                          return_value=fake_results):
            check_report(report, tmp_path)
            check_report(report, tmp_path)
        assert report.read_text().count(bl._SECTION_MARKER) == 1
