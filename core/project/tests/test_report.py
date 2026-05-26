"""Tests for project report — merged view across all runs."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.project import Project
from core.project.report import (
    generate_project_report,
    render_grouped_findings_markdown,
)
from core.run import start_run, complete_run


def _sca_row(name, *, severity="high", escalation_reasons=None):
    sca = {"kind": "slopsquat_suspect", "ecosystem": "npm", "name": name}
    if escalation_reasons is not None:
        sca["evidence"] = {"escalation_reasons": escalation_reasons}
    return {
        "id": f"sca:supply_chain:slopsquat_suspect:npm:{name}",
        "finding_id": f"sca:supply_chain:slopsquat_suspect:npm:{name}",
        "vuln_type": "sca:supply_chain:slopsquat_suspect",
        "tool": "sca", "file": "package.json", "function": name, "line": 0,
        "severity": severity, "title": f"Slopsquat suspect: {name}",
        "sca": sca,
    }


class TestProjectReport(unittest.TestCase):

    def _make_project(self, tmpdir, runs, sca_runs=None):
        output_dir = Path(tmpdir) / "project"
        output_dir.mkdir()
        for name, findings in runs.items():
            run_dir = output_dir / name
            start_run(run_dir, "scan")
            complete_run(run_dir)
            (run_dir / "findings.json").write_text(json.dumps(findings))
            sca_rows = (sca_runs or {}).get(name)
            if sca_rows is not None:
                (run_dir / "sca").mkdir()
                (run_dir / "sca" / "findings.json").write_text(json.dumps(sca_rows))
        return Project(name="test", target=str(Path(tmpdir) / "code"),
                       output_dir=str(output_dir))

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

    def test_sca_findings_in_report(self):
        """SCA findings (from each run's sca/ subdir) are counted and
        appear in the aggregate report markdown under their own section."""
        with TemporaryDirectory() as d:
            p = self._make_project(
                d,
                {"scan-1": [{"id": "F-001", "file": "a.c", "function": "main", "line": 10}]},
                sca_runs={"scan-1": [_sca_row("lodash-pro")]},
            )
            stats = generate_project_report(p)
            self.assertEqual(stats["findings"], 1)
            self.assertEqual(stats["sca_findings"], 1)
            agg = next((p.output_path / "findings").glob("*.md"))
            text = agg.read_text(encoding="utf-8")
            self.assertIn("Supply chain / dependencies (SCA)", text)
            self.assertIn("npm:lodash-pro", text)

    def test_real_slopsquat_surfaces_in_report_e2e(self):
        """Cross-package E2E: a slopsquat from the REAL SCA detector +
        REAL serializer surfaces in the generated project report. Guards
        the on-disk contract (SCA findings.json shape vs report reader).
        Skipped if the optional SCA package isn't importable."""
        try:
            from packages.sca.parsers.package_json import parse as parse_pkg
            from packages.sca.supply_chain import _slopsquat_to_finding
            from packages.sca.supply_chain.slopsquat import check_dep
            from packages.sca.findings import write_findings_json
        except ImportError:
            self.skipTest("optional SCA package not importable")

        with TemporaryDirectory() as d:
            p = self._make_project(d, {
                "scan-1": [{"id": "F-1", "file": "a.c", "function": "main", "line": 1}],
            })
            run_dir = p.output_path / "scan-1"
            pkg = run_dir / "pkg" / "package.json"
            pkg.parent.mkdir(parents=True)
            pkg.write_text(json.dumps({
                "name": "victim", "dependencies": {"lodash-pro": "^1.0.0"},
            }))
            deps = parse_pkg(pkg)
            ss = [f for f in (check_dep(dep) for dep in deps) if f]
            self.assertTrue(ss, "real detector found no slopsquat in 'lodash-pro'")
            write_findings_json(
                run_dir / "sca" / "findings.json",
                supply_chain_findings=[_slopsquat_to_finding(f) for f in ss],
            )
            stats = generate_project_report(p)
            self.assertEqual(stats["sca_findings"], len(ss))
            agg = next((p.output_path / "findings").glob("*.md"))
            text = agg.read_text(encoding="utf-8")
            self.assertIn("Supply chain / dependencies (SCA)", text)
            self.assertIn("lodash-pro", text)

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
            p = Project(name="test", target=str(Path(d) / "code"),
                        output_dir=str(output_dir))
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


class TestRenderGroupedFindingsMarkdownSca(unittest.TestCase):

    def test_sca_section_appended(self):
        code = [{"id": "F-1", "file": "a.c", "function": "main",
                 "severity": "high", "title": "Overflow"}]
        sca = [_sca_row("lodash-pro", severity="medium")]
        md = render_grouped_findings_markdown(code, "proj", sca_findings=sca)
        self.assertIn("## Supply chain / dependencies (SCA)", md)
        self.assertIn("npm:lodash-pro", md)
        # Code finding still rendered under its severity heading.
        self.assertIn("## High", md)

    def test_no_sca_no_section(self):
        code = [{"id": "F-1", "file": "a.c", "severity": "high", "title": "X"}]
        md = render_grouped_findings_markdown(code, "proj")
        self.assertNotIn("Supply chain", md)

    def test_sca_only_not_no_findings(self):
        md = render_grouped_findings_markdown(
            [], "proj", sca_findings=[_sca_row("expresss")])
        self.assertNotIn("No findings.", md)
        self.assertIn("## Supply chain / dependencies (SCA)", md)

    def test_escalation_reasons_rendered_as_sub_bullet(self):
        sca = [_sca_row("react-helper", severity="critical",
                        escalation_reasons=[
                            "co-occurs with recent_publish + low_bus_factor"])]
        md = render_grouped_findings_markdown([], "proj", sca_findings=sca)
        self.assertIn("escalated: co-occurs with recent_publish", md)

    def test_no_escalation_reasons_no_sub_bullet(self):
        md = render_grouped_findings_markdown(
            [], "proj", sca_findings=[_sca_row("react-helper")])
        self.assertNotIn("escalated:", md)


if __name__ == "__main__":
    unittest.main()
