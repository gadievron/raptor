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
                "scan-20260401": [{"id": "F-001"}, {"id": "F-002"}],
                "scan-20260402": [{"id": "F-002"}, {"id": "F-003"}],
            })
            stats = generate_project_report(p)
            self.assertEqual(stats["findings"], 3)  # F-001, F-002, F-003
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


if __name__ == "__main__":
    unittest.main()
