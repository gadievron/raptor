"""Tests for coverage summary computation and formatting."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.coverage.summary import (
    compute_summary,
    compute_project_summary,
    coverage_threshold_met,
    format_summary,
    format_threshold_result,
    llm_item_coverage_percent,
)
from core.coverage.record import write_record


class TestComputeSummary(unittest.TestCase):

    def _write_checklist(self, d, files=None):
        if files is None:
            files = [
                {"path": "src/auth.c", "sloc": 100, "items": [
                    {"name": "check_pw", "line_start": 10, "line_end": 40},
                    {"name": "login", "line_start": 50, "line_end": 80},
                ]},
                {"path": "src/db.c", "sloc": 200, "items": [
                    {"name": "query", "line_start": 5, "line_end": 50},
                ]},
            ]
        checklist = {"files": files, "total_files": len(files)}
        (Path(d) / "checklist.json").write_text(json.dumps(checklist))

    def test_basic_summary(self):
        with TemporaryDirectory() as d:
            self._write_checklist(d)
            summary = compute_summary(d)
            self.assertEqual(summary["inventory"]["files"], 2)
            self.assertEqual(summary["inventory"]["sloc"], 300)
            self.assertEqual(summary["inventory"]["items"], 3)

    def test_no_checklist(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(compute_summary(d))

    def test_semgrep_coverage(self):
        with TemporaryDirectory() as d:
            self._write_checklist(d)
            write_record(Path(d), {
                "tool": "semgrep",
                "files_examined": ["src/auth.c", "src/db.c"],
                "rules_applied": ["injection", "crypto"],
            }, tool_name="semgrep")
            summary = compute_summary(d)
            self.assertEqual(summary["tools"]["semgrep"]["files_examined"], 2)
            self.assertEqual(summary["tools"]["semgrep"]["rules_applied"], ["injection", "crypto"])

    def test_codeql_coverage(self):
        with TemporaryDirectory() as d:
            self._write_checklist(d)
            write_record(Path(d), {
                "tool": "codeql",
                "files_examined": ["src/auth.c"],
                "packs": ["codeql/cpp-queries@1.0.0"],
                "rules_applied": ["cpp/overflow"],
                "files_failed": [{"path": "src/db.c", "reason": "build error"}],
            }, tool_name="codeql")
            summary = compute_summary(d)
            self.assertEqual(summary["tools"]["codeql"]["files_examined"], 1)
            self.assertEqual(len(summary["tools"]["codeql"]["files_failed"]), 1)

    def test_llm_coverage(self):
        with TemporaryDirectory() as d:
            self._write_checklist(d)
            write_record(Path(d), {
                "tool": "llm",
                "files_examined": ["src/auth.c"],
                "functions_analysed": [
                    {"file": "src/auth.c", "function": "check_pw"},
                ],
            }, tool_name="llm")
            summary = compute_summary(d)
            self.assertEqual(summary["tools"]["llm"]["functions_analysed"], 1)
            self.assertEqual(summary["tools"]["llm"]["functions_total"], 3)
            self.assertEqual(summary["unreviewed_functions"], 2)

    def test_multiple_tools(self):
        with TemporaryDirectory() as d:
            self._write_checklist(d)
            write_record(Path(d), {
                "tool": "semgrep",
                "files_examined": ["src/auth.c", "src/db.c"],
            }, tool_name="semgrep")
            write_record(Path(d), {
                "tool": "llm",
                "files_examined": ["src/auth.c"],
                "functions_analysed": [
                    {"file": "src/auth.c", "function": "check_pw"},
                    {"file": "src/auth.c", "function": "login"},
                ],
            }, tool_name="llm")
            summary = compute_summary(d)
            self.assertIn("semgrep", summary["tools"])
            self.assertIn("llm", summary["tools"])
            self.assertEqual(summary["unreviewed_functions"], 1)

    def test_per_file_breakdown(self):
        with TemporaryDirectory() as d:
            self._write_checklist(d)
            write_record(Path(d), {
                "tool": "llm",
                "files_examined": ["src/auth.c"],
                "functions_analysed": [
                    {"file": "src/auth.c", "function": "check_pw"},
                ],
            }, tool_name="llm")
            summary = compute_summary(d)
            per_file = summary["per_file"]
            self.assertEqual(len(per_file), 2)
            # Worst first: db.c has 0%, auth.c has 50%
            self.assertEqual(per_file[0]["path"], "src/db.c")
            self.assertEqual(per_file[0]["reviewed"], 0)
            self.assertEqual(per_file[1]["path"], "src/auth.c")
            self.assertEqual(per_file[1]["reviewed"], 1)

    def test_missing_semgrep_groups(self):
        with TemporaryDirectory() as d:
            self._write_checklist(d)
            write_record(Path(d), {
                "tool": "semgrep",
                "files_examined": ["src/auth.c"],
                "rules_applied": ["crypto"],
            }, tool_name="semgrep")
            summary = compute_summary(d)
            missing = summary["missing_groups"]
            self.assertIn("injection", missing)
            self.assertNotIn("crypto", missing)


class TestFormatSummary(unittest.TestCase):

    def test_formats_basic(self):
        summary = {
            "inventory": {"files": 10, "sloc": 1000, "items": 25},
            "tools": {
                "semgrep": {
                    "files_examined": 10, "files_total": 10,
                    "rules_applied": ["injection", "crypto"],
                },
            },
            "unreviewed_functions": 25,
            "unreviewed_sloc": 1000,
            "missing_groups": ["auth", "secrets"],
            "per_file": [],
        }
        text = format_summary(summary)
        self.assertIn("Inventory: 10 files", text)
        self.assertIn("Semgrep: 10/10 files", text)
        self.assertIn("2 groups", text)
        self.assertIn("25 items not reviewed by LLM", text)
        self.assertIn("2 Semgrep policy groups not used", text)

    def test_formats_codeql(self):
        summary = {
            "inventory": {"files": 5, "sloc": 500, "items": 10},
            "tools": {
                "codeql": {
                    "files_examined": 3, "files_total": 5,
                    "packs": ["codeql/cpp-queries@1.0.0"],
                    "rules_applied": ["a", "b"],
                },
            },
            "unreviewed_functions": 10,
            "unreviewed_sloc": 500,
            "missing_groups": [],
            "per_file": [],
        }
        text = format_summary(summary)
        self.assertIn("CodeQL: 3/5 files", text)
        self.assertIn("codeql/cpp-queries@1.0.0", text)
        self.assertIn("2 rules", text)

    def test_no_data(self):
        self.assertEqual(format_summary(None), "No coverage data available.")

    def test_llm_item_coverage_threshold_helpers(self):
        summary = {
            "inventory": {"files": 2, "sloc": 120, "items": 4},
            "tools": {
                "llm": {
                    "files_examined": 1,
                    "files_total": 2,
                    "functions_analysed": 3,
                    "functions_total": 4,
                }
            },
            "unreviewed_functions": 1,
            "unreviewed_sloc": 30,
            "missing_groups": [],
            "per_file": [],
        }
        self.assertEqual(llm_item_coverage_percent(summary), 75.0)
        self.assertTrue(coverage_threshold_met(summary, 75.0))
        self.assertFalse(coverage_threshold_met(summary, 80.0))
        self.assertIn("75.0% LLM item coverage", format_threshold_result(summary, 80.0))
        self.assertIn("FAIL", format_threshold_result(summary, 80.0))


class TestProjectSummary(unittest.TestCase):

    def test_merges_across_runs(self):
        """Coverage from multiple runs is accumulated."""
        from core.project.project import Project
        with TemporaryDirectory() as d:
            # Create two run dirs with different coverage
            run1 = Path(d) / "scan-20260401"
            run1.mkdir()
            run2 = Path(d) / "validate-20260402"
            run2.mkdir()

            checklist = {"files": [
                {"path": "src/a.c", "sloc": 50, "items": [
                    {"name": "foo", "line_start": 1, "line_end": 25},
                    {"name": "bar", "line_start": 30, "line_end": 50},
                ]},
                {"path": "src/b.c", "sloc": 50, "items": [
                    {"name": "baz", "line_start": 1, "line_end": 50},
                ]},
            ]}
            # Project-level checklist
            (Path(d) / "checklist.json").write_text(json.dumps(checklist))

            # Run 1: semgrep scanned both files
            write_record(run1, {
                "tool": "semgrep",
                "files_examined": ["src/a.c", "src/b.c"],
                "rules_applied": ["crypto"],
            }, tool_name="semgrep")

            # Run 2: LLM analysed one function
            write_record(run2, {
                "tool": "llm",
                "files_examined": ["src/a.c"],
                "functions_analysed": [{"file": "src/a.c", "function": "foo"}],
            }, tool_name="llm")

            p = Project(name="test", target="/tmp", output_dir=d)
            summary = compute_project_summary(p)

            self.assertEqual(summary["tools"]["semgrep"]["files_examined"], 2)
            self.assertEqual(summary["tools"]["llm"]["functions_analysed"], 1)
            self.assertEqual(summary["unreviewed_functions"], 2)

    def test_no_checklist(self):
        from core.project.project import Project
        with TemporaryDirectory() as d:
            p = Project(name="test", target="/tmp", output_dir=d)
            self.assertIsNone(compute_project_summary(p))

    def test_no_records(self):
        """With checklist but no coverage records, still returns inventory."""
        from core.project.project import Project
        with TemporaryDirectory() as d:
            (Path(d) / "checklist.json").write_text(json.dumps({
                "files": [{"path": "a.c", "sloc": 10, "items": [{"name": "main"}]}]
            }))
            p = Project(name="test", target="/tmp", output_dir=d)
            summary = compute_project_summary(p)
            self.assertEqual(summary["inventory"]["files"], 1)
            self.assertEqual(summary["tools"], {})


if __name__ == "__main__":
    unittest.main()
