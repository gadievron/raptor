"""Tests for per-run tool EXECUTION detail (record-backed) — the record side
of the unified coverage report. Coverage *state* is tested in test_store_summary.py.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.coverage.summary import (
    _match_to_inventory,
    execution_detail,
    format_execution_detail,
)
from core.coverage.record import write_record

_CHECKLIST = {"files": [
    {"path": "src/auth.c", "sloc": 100, "lines": 100, "items": [
        {"name": "check_pw", "line_start": 10, "line_end": 40},
        {"name": "login", "line_start": 50, "line_end": 80}]},
    {"path": "src/db.c", "sloc": 200, "lines": 200, "items": [
        {"name": "query", "line_start": 5, "line_end": 50}]},
]}


class TestExecutionDetail(unittest.TestCase):

    def test_semgrep_files_and_rules(self):
        with TemporaryDirectory() as d:
            write_record(Path(d), {
                "tool": "semgrep",
                "files_examined": ["src/auth.c", "src/db.c"],
                "rules_applied": ["injection", "crypto"],
            }, tool_name="semgrep")
            t = execution_detail([Path(d)], _CHECKLIST)["tools"]["semgrep"]
            self.assertEqual(t["files_examined"], 2)
            self.assertEqual(t["files_total"], 2)
            self.assertEqual(t["rules_applied"], ["crypto", "injection"])

    def test_codeql_packs_and_files_failed(self):
        with TemporaryDirectory() as d:
            write_record(Path(d), {
                "tool": "codeql",
                "files_examined": ["src/auth.c"],
                "packs": ["codeql/cpp-queries@1.0.0"],
                "rules_applied": ["cpp/overflow"],
                "files_failed": [{"path": "src/db.c", "reason": "build error"}],
            }, tool_name="codeql")
            t = execution_detail([Path(d)], _CHECKLIST)["tools"]["codeql"]
            self.assertEqual(t["files_examined"], 1)
            self.assertEqual(t["packs"], ["codeql/cpp-queries@1.0.0"])
            self.assertEqual(len(t["files_failed"]), 1)

    def test_absolute_path_matched_to_inventory(self):
        with TemporaryDirectory() as d:
            write_record(Path(d), {
                "tool": "semgrep",
                "files_examined": ["/abs/root/src/auth.c"],   # tool emits abs
            }, tool_name="semgrep")
            t = execution_detail([Path(d)], _CHECKLIST)["tools"]["semgrep"]
            self.assertEqual(t["files_examined"], 1)           # matched, counted

    def test_missing_semgrep_groups(self):
        with TemporaryDirectory() as d:
            write_record(Path(d), {
                "tool": "semgrep",
                "files_examined": ["src/auth.c"],
                "rules_applied": ["crypto"],
            }, tool_name="semgrep")
            detail = execution_detail([Path(d)], _CHECKLIST)
            self.assertIn("injection", detail["missing_groups"])
            self.assertNotIn("crypto", detail["missing_groups"])

    def test_merges_across_run_dirs(self):
        with TemporaryDirectory() as d:
            r1 = Path(d) / "scan-1"
            r1.mkdir()
            r2 = Path(d) / "validate-2"
            r2.mkdir()
            write_record(r1, {"tool": "semgrep", "files_examined": ["src/auth.c"]},
                         tool_name="semgrep")
            write_record(r2, {"tool": "semgrep", "files_examined": ["src/db.c"]},
                         tool_name="semgrep")
            t = execution_detail([r1, r2], _CHECKLIST)["tools"]["semgrep"]
            self.assertEqual(t["files_examined"], 2)           # union across runs

    def test_no_records_is_empty(self):
        with TemporaryDirectory() as d:
            detail = execution_detail([Path(d)], _CHECKLIST)
            self.assertEqual(detail["tools"], {})
            self.assertEqual(detail["missing_groups"], [])


class TestFormatExecutionDetail(unittest.TestCase):

    def test_renders_tools_and_missing(self):
        detail = {"tools": {"semgrep": {
            "files_examined": 1, "files_total": 2, "rules_applied": ["crypto"],
            "packs": [], "files_failed": [], "version": "1.0"}},
            "missing_groups": ["injection", "auth"]}
        text = format_execution_detail(detail)
        self.assertIn("semgrep", text)
        self.assertIn("1/2 files", text)
        self.assertIn("Semgrep policy group(s) not used", text)

    def test_empty_renders_blank(self):
        self.assertEqual(format_execution_detail({"tools": {}}), "")


class TestMatchToInventory(unittest.TestCase):

    def test_exact_relative_and_absolute(self):
        inv = {"src/auth.c", "src/db.c"}
        self.assertEqual(_match_to_inventory("src/auth.c", inv), "src/auth.c")
        self.assertEqual(_match_to_inventory("./src/db.c", inv), "src/db.c")
        self.assertEqual(_match_to_inventory("/abs/src/auth.c", inv), "src/auth.c")
        self.assertIsNone(_match_to_inventory("nope.c", inv))


if __name__ == "__main__":
    unittest.main()
