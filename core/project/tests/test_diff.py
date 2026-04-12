"""Tests for findings diff between runs."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.diff import diff_runs


class TestDiffRuns(unittest.TestCase):

    def _make_run(self, tmpdir, name, findings):
        """Create a run directory with findings.json."""
        run_dir = Path(tmpdir) / name
        run_dir.mkdir()
        (run_dir / "findings.json").write_text(json.dumps(findings))
        return run_dir

    def test_new_findings(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}},
            ])
            b = self._make_run(d, "b", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}},
                {"id": "F-002", "file": "b.c", "function": "foo", "line": 20, "ruling": {"status": "exploitable"}},
            ])
            result = diff_runs(a, b)
            self.assertEqual(len(result["new"]), 1)
            self.assertEqual(result["new"][0]["file"], "b.c")

    def test_removed_findings(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}},
                {"id": "F-002", "file": "b.c", "function": "foo", "line": 20, "ruling": {"status": "exploitable"}},
            ])
            b = self._make_run(d, "b", [
                {"id": "F-100", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}},
            ])
            result = diff_runs(a, b)
            self.assertEqual(len(result["removed"]), 1)
            self.assertEqual(result["removed"][0]["file"], "b.c")

    def test_changed_findings(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}},
            ])
            b = self._make_run(d, "b", [
                {"id": "F-100", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "exploitable"}},
            ])
            result = diff_runs(a, b)
            self.assertEqual(len(result["changed"]), 1)
            self.assertEqual(result["changed"][0]["label"], "a.c:main:10")
            self.assertEqual(result["changed"][0]["status_before"], "confirmed")
            self.assertEqual(result["changed"][0]["status_after"], "exploitable")

    def test_matches_by_location_not_id(self):
        """Same location with different IDs should match as same finding."""
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}},
            ])
            b = self._make_run(d, "b", [
                {"id": "F-999", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}},
            ])
            result = diff_runs(a, b)
            self.assertEqual(result["unchanged"], 1)
            self.assertEqual(len(result["new"]), 0)
            self.assertEqual(len(result["removed"]), 0)

    def test_unchanged_count(self):
        with TemporaryDirectory() as d:
            findings_a = [
                {"id": "F-001", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}},
                {"id": "F-002", "file": "b.c", "function": "foo", "line": 20, "ruling": {"status": "exploitable"}},
            ]
            findings_b = [
                {"id": "F-100", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}},
                {"id": "F-200", "file": "b.c", "function": "foo", "line": 20, "ruling": {"status": "exploitable"}},
            ]
            a = self._make_run(d, "a", findings_a)
            b = self._make_run(d, "b", findings_b)
            result = diff_runs(a, b)
            self.assertEqual(result["unchanged"], 2)
            self.assertEqual(len(result["new"]), 0)
            self.assertEqual(len(result["removed"]), 0)
            self.assertEqual(len(result["changed"]), 0)

    def test_empty_runs(self):
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [])
            b = self._make_run(d, "b", [])
            result = diff_runs(a, b)
            self.assertEqual(result["unchanged"], 0)
            self.assertEqual(len(result["new"]), 0)

    def test_missing_findings_json(self):
        with TemporaryDirectory() as d:
            a = Path(d) / "a"
            a.mkdir()
            b = self._make_run(d, "b", [{"id": "F-001", "file": "a.c", "function": "main", "line": 10}])
            result = diff_runs(a, b)
            self.assertEqual(len(result["new"]), 1)

    def test_findings_in_envelope(self):
        """findings.json may wrap findings in a dict."""
        with TemporaryDirectory() as d:
            a = Path(d) / "a"
            a.mkdir()
            (a / "findings.json").write_text(json.dumps({
                "stage": "D", "findings": [
                    {"id": "F-001", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "confirmed"}}
                ]
            }))
            b = Path(d) / "b"
            b.mkdir()
            (b / "findings.json").write_text(json.dumps({
                "stage": "D", "findings": [
                    {"id": "F-100", "file": "a.c", "function": "main", "line": 10, "ruling": {"status": "exploitable"}}
                ]
            }))
            result = diff_runs(a, b)
            self.assertEqual(len(result["changed"]), 1)

    def test_agentic_format(self):
        """Agentic findings use is_exploitable boolean."""
        with TemporaryDirectory() as d:
            a = self._make_run(d, "a", [
                {"finding_id": "SARIF-001", "file": "a.c", "function": "main", "line": 5, "is_exploitable": True},
            ])
            b = self._make_run(d, "b", [
                {"finding_id": "SARIF-002", "file": "a.c", "function": "main", "line": 5, "is_exploitable": False},
            ])
            result = diff_runs(a, b)
            self.assertEqual(len(result["changed"]), 1)


if __name__ == "__main__":
    unittest.main()
