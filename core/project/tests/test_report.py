"""Tests for project report — merged view across all runs."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.project import Project
from core.project.report import generate_project_report
from core.run import start_run, complete_run


class TestProjectReport(unittest.TestCase):

    def _make_project(self, tmpdir, runs):
        output_dir = Path(tmpdir) / "project"
        output_dir.mkdir()
        for name, findings in runs.items():
            run_dir = output_dir / name
            start_run(run_dir, "scan")
            complete_run(run_dir)
            (run_dir / "findings.json").write_text(json.dumps(findings))
        return Project(name="test", target="/tmp/code", output_dir=str(output_dir))

    def test_merged_findings(self):
        with TemporaryDirectory() as d:
            p = self._make_project(d, {
                "scan-20260401": [
                    {"id": "F-001", "file": "a.c", "function": "main", "line": 10},
                    {"id": "F-002", "file": "b.c", "function": "foo", "line": 20},
                ],
                "scan-20260402": [
                    {"id": "F-002", "file": "b.c", "function": "foo", "line": 20},
                    {"id": "F-003", "file": "c.c", "function": "bar", "line": 30},
                ],
            })
            stats = generate_project_report(p)
            self.assertEqual(stats["findings"], 3)  # a.c, b.c, c.c
            self.assertEqual(stats["runs"], 2)

    def test_report_dir_created(self):
        with TemporaryDirectory() as d:
            p = self._make_project(d, {
                "scan-20260401": [{"id": "F-001"}],
            })
            generate_project_report(p)
            self.assertTrue((p.output_path / "_report" / "findings.json").exists())

    def test_idempotent(self):
        with TemporaryDirectory() as d:
            p = self._make_project(d, {
                "scan-20260401": [{"id": "F-001"}],
            })
            stats1 = generate_project_report(p)
            stats2 = generate_project_report(p)
            self.assertEqual(stats1["findings"], stats2["findings"])

    def test_runs_preserved(self):
        with TemporaryDirectory() as d:
            p = self._make_project(d, {
                "scan-20260401": [{"id": "F-001"}],
            })
            generate_project_report(p)
            # Original run still exists
            self.assertTrue((p.output_path / "scan-20260401" / "findings.json").exists())

    def test_empty_project(self):
        with TemporaryDirectory() as d:
            output_dir = Path(d) / "empty"
            output_dir.mkdir()
            p = Project(name="test", target="/tmp", output_dir=str(output_dir))
            stats = generate_project_report(p)
            self.assertEqual(stats["findings"], 0)
            self.assertEqual(stats["runs"], 0)

    def test_report_excludes_report_dir(self):
        """_report/ directory should not be read as a run."""
        with TemporaryDirectory() as d:
            p = self._make_project(d, {
                "scan-20260401": [{"id": "F-001"}],
            })
            # Generate report, then regenerate — _report/ should not add findings
            generate_project_report(p)
            stats = generate_project_report(p)
            self.assertEqual(stats["findings"], 1)  # Not 2

    def test_report_writes_grouped_markdown_findings(self):
        with TemporaryDirectory() as d:
            p = self._make_project(d, {
                "scan-20260401": [
                    {
                        "id": "RPT-001",
                        "title": "Command injection",
                        "status": "confirmed",
                        "severity": "high",
                        "file": "src/app.py",
                        "function": "handler",
                        "line": 42,
                        "vuln_type": "command_injection",
                        "evidence": "attacker-controlled argument reaches subprocess",
                    },
                    {
                        "id": "RPT-002",
                        "title": "Dead code report",
                        "status": "ruled_out",
                        "file": "src/legacy.py",
                        "function": "old_handler",
                    },
                    {
                        "id": "RPT-003",
                        "title": "Needs triage",
                        "status": "not_disproven",
                        "file": "src/review.py",
                    },
                ],
            })

            stats = generate_project_report(p)

            findings_dir = p.output_path / "findings"
            self.assertEqual(stats["finding_buckets"], {
                "confirmed": 1,
                "needs-review": 1,
                "ruled-out": 1,
            })
            self.assertTrue((findings_dir / "manifest.json").exists())
            self.assertTrue((findings_dir / "findings.jsonl").exists())
            self.assertTrue((findings_dir / "test.md").exists())
            self.assertEqual(len(list((findings_dir / "confirmed").glob("*.md"))), 1)
            self.assertEqual(len(list((findings_dir / "ruled-out").glob("*.md"))), 1)
            self.assertEqual(len(list((findings_dir / "needs-review").glob("*.md"))), 1)
            aggregate = (findings_dir / "test.md").read_text()
            self.assertIn("# test findings", aggregate)
            self.assertLess(aggregate.index("## High"), aggregate.index("## Unknown"))
            markdown = next((findings_dir / "confirmed").glob("*.md")).read_text()
            self.assertIn("# Command injection", markdown)
            self.assertIn("Stable fingerprint:", markdown)
            self.assertIn("| Severity | high |", markdown)
            self.assertIn("attacker-controlled argument reaches subprocess", markdown)

    def test_generated_findings_directory_is_not_treated_as_run(self):
        with TemporaryDirectory() as d:
            p = self._make_project(d, {
                "scan-20260401": [{"id": "F-001", "status": "confirmed"}],
            })
            generate_project_report(p)
            stats = generate_project_report(p)
            self.assertEqual(stats["runs"], 1)
            self.assertEqual(stats["findings"], 1)


if __name__ == "__main__":
    unittest.main()
