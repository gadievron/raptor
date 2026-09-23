#!/usr/bin/env python3
"""Tests for the blamed-line execution check."""

import json
from pathlib import Path
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
             patch.object(bl, "_run_checker", return_value=fake):
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
             patch.object(bl, "_run_checker", return_value=fake):
            results = check_blamed_lines([("b.c", 9)], cov)
        assert results[0].status == "unknown"
        assert "No coverage data" in results[0].reason

    def test_missing_output_line_unknown(self, tmp_path):
        cov = self._coverage_dir(tmp_path)
        fake = self._fake_proc(returncode=0, stdout="a.c:1 EXECUTED (2 times)\n")
        with patch.object(bl, "_resolve_checker",
                          return_value=cov / "line-checker"), \
             patch.object(bl, "_run_checker", return_value=fake):
            results = check_blamed_lines([("a.c", 1), ("a.c", 7)], cov)
        assert results[1].status == "unknown"


class TestCheckerProvenance:
    """The checker must never come from (or run outside the sandbox
    over) target-writable state. The coverage dir is written by the
    instrumented target's own build and execution, so a pre-existing
    ``line-checker`` there is attacker-plantable — executing it is
    host code execution plus a forgeable coverage oracle."""

    def _covdir_with_planted_checker(self, tmp_path):
        cov = tmp_path / "covdir"
        cov.mkdir()
        (cov / "fake.gcov").write_text("", encoding="utf-8")
        marker = tmp_path / "PWNED-OUTSIDE-SANDBOX"
        planted = cov / "line-checker"
        planted.write_text(
            "#!/bin/sh\n"
            f"touch {marker}\n"
            'echo "x.c:10 EXECUTED (5 times)"\n',
            encoding="utf-8")
        planted.chmod(0o755)
        return cov, marker

    def test_planted_coverage_dir_checker_never_executed(self, tmp_path):
        cov, marker = self._covdir_with_planted_checker(tmp_path)
        # raptor_dir without the skill source: with the planted binary
        # correctly distrusted there is nothing to build, so the only
        # honest answer is "unavailable" — never the planted verdict.
        results = check_blamed_lines(
            [("x.c", 10)], cov, raptor_dir=tmp_path / "empty-root")
        assert [r.status for r in results] == ["unknown"]
        assert "unavailable" in results[0].reason
        assert not marker.exists(), (
            "planted line-checker from the target-writable coverage "
            "dir was executed")

    def test_build_lands_in_raptor_owned_scratch_not_coverage_dir(
            self, tmp_path):
        cov, _ = self._covdir_with_planted_checker(tmp_path)
        root = tmp_path / "raptor-root"
        cpp = root / bl._SKILL_CPP
        cpp.parent.mkdir(parents=True)
        cpp.write_text("int main(){return 0;}\n", encoding="utf-8")
        build_cmds = []

        def fake_build(argv, **kwargs):
            build_cmds.append(argv)
            return self._fake_proc(returncode=1)  # build "fails": stop early

        with patch.object(bl.subprocess, "run", side_effect=fake_build):
            check_blamed_lines([("x.c", 10)], cov, raptor_dir=root)
        assert build_cmds, "checker build was never attempted"
        out_path = Path(build_cmds[0][build_cmds[0].index("-o") + 1])
        assert cov.resolve() not in out_path.resolve().parents, (
            "checker built into the target-writable coverage dir")

    def _fake_proc(self, returncode=0, stdout="", stderr=""):
        class _P:
            pass
        p = _P()
        p.returncode = returncode
        p.stdout = stdout
        p.stderr = stderr
        return p

    def test_checker_execution_routes_through_full_sandbox(self, tmp_path):
        cov = tmp_path / "covdir"
        cov.mkdir()
        (cov / "a.c.gcov").write_text("", encoding="utf-8")
        checker = tmp_path / "scratch" / "line-checker"
        checker.parent.mkdir()
        checker.write_text("", encoding="utf-8")
        calls = []

        def fake_sandbox_run(argv, **kwargs):
            calls.append((argv, kwargs))
            return self._fake_proc(returncode=0,
                                   stdout="a.c:1 EXECUTED (2 times)\n")

        import core.sandbox
        with patch.object(bl, "_resolve_checker", return_value=checker), \
             patch.object(core.sandbox, "run", fake_sandbox_run):
            results = check_blamed_lines([("a.c", 1)], cov)
        assert results[0].status == "executed"
        assert calls, "checker did not go through core.sandbox.run"
        argv, kwargs = calls[0]
        assert argv[0] == str(checker)
        assert kwargs["block_network"] is True
        assert kwargs["target"] == str(cov)

    def test_sandbox_setup_failure_degrades_to_unknown_never_unsandboxed(
            self, tmp_path):
        cov = tmp_path / "covdir"
        cov.mkdir()
        (cov / "a.c.gcov").write_text("", encoding="utf-8")
        checker = tmp_path / "line-checker"
        checker.write_text("", encoding="utf-8")

        class _SetupBoom(BaseException):
            pass

        def raise_setup(*a, **k):
            raise _SetupBoom("no enforcing layer")

        with patch.object(bl, "_resolve_checker", return_value=checker), \
             patch.object(bl, "_run_checker", side_effect=raise_setup):
            results = check_blamed_lines([("a.c", 1)], cov)
        assert results[0].status == "unknown"
        assert "sandbox unavailable" in results[0].reason


class TestRenderAndStamp:
    def test_hostile_reason_cell_defanged(self):
        """The reason cell carries up to 200 chars of checker stderr —
        hostile-gcov-derived bytes. A raw pipe breaks the table row, a
        newline splits the line, image markup autofetches on render."""
        section = render_section([
            BlamedLineResult(
                "x.c", 10, "unknown",
                reason="a|b\nc ![x](http://evil.example/x)"),
        ])
        row = next(ln for ln in section.splitlines()
                   if ln.startswith("| ") and "x.c" in ln)
        assert row.count("|") == 3, "raw pipe broke the table row"
        assert "](http://evil.example/x)" not in section, (
            "live image/link markup survives into the report")

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

    def test_prose_containing_delimiter_survives_stamping(self, tmp_path):
        """Agent prose that legitimately contains the delimiter byte
        sequence must not be truncated — only a previously stamped
        (footer-verified) mechanical section is replaced."""
        prose_tail = (
            "\n---\n\n" + bl._SECTION_MARKER
            + "\n\nThe agent quotes the section header in its "
            "discussion here.\n\n### Step 5: Conclusion\n"
            "**Location:** `src/parser.c:300`\n"
        )
        report = tmp_path / "root-cause-hypothesis-1.md"
        report.write_text(REPORT + prose_tail, encoding="utf-8")
        fake_results = [BlamedLineResult("src/parser.c", 120, "executed",
                                         count=1)]
        with patch.object(bl, "check_blamed_lines",
                          return_value=fake_results):
            check_report(report, tmp_path)
            check_report(report, tmp_path)
        text = report.read_text()
        assert "Step 5: Conclusion" in text, "agent prose truncated"
        assert text.count(bl._SECTION_FOOTER) == 1
