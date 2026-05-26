"""Basic smoke tests for the project CLI."""

import contextlib
import io
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.cli import (
    _get_active_project,
    _get_output_summary,
    _print_findings,
    _print_sca_findings_section,
    _sca_finding_escalations,
    _sca_finding_kind,
    _sca_finding_package,
    main,
)


class _FakeProject:
    """Minimal stand-in: _print_findings only calls get_run_dirs()."""

    def __init__(self, run_dirs):
        self._run_dirs = run_dirs

    def get_run_dirs(self, sweep=False):
        return self._run_dirs


def _sca_finding(name, *, severity="high", escalation_reasons=None):
    sca = {"kind": "slopsquat_suspect", "ecosystem": "npm", "name": name}
    if escalation_reasons is not None:
        sca["evidence"] = {"escalation_reasons": escalation_reasons}
    return {
        "id": f"SCA-{name}", "finding_id": f"SCA-{name}",
        "vuln_type": "sca:supply_chain:slopsquat_suspect", "tool": "sca",
        "file": "package.json", "function": name, "line": 0,
        "severity": severity, "title": f"Slopsquat suspect: {name}",
        "description": "looks like an LLM-hallucinated package name",
        "sca": sca,
    }


def _write_sca(run_dir: Path, rows):
    (run_dir / "sca").mkdir(parents=True, exist_ok=True)
    (run_dir / "sca" / "findings.json").write_text(json.dumps(rows), encoding="utf-8")


class TestRunSummarySca(unittest.TestCase):
    """The per-run summary count (run list) includes SCA findings, so it
    matches what /project findings shows."""

    def test_sca_only_run_counted(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("lodash-pro")])
            # meta with no status → computed, not cached/written back.
            self.assertEqual(_get_output_summary(run_dir, {}), "1 findings")

    def test_code_plus_sca_combined(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            (run_dir / "findings.json").write_text(json.dumps([
                {"id": "F-1", "file": "a.c", "function": "main", "line": 5,
                 "vuln_type": "buffer_overflow"},
            ]), encoding="utf-8")
            _write_sca(run_dir, [_sca_finding("expresss")])
            self.assertEqual(_get_output_summary(run_dir, {}), "2 findings")

    def test_stale_v1_cache_recomputed(self):
        """A pre-SCA cached summary (no version, or version != current)
        must NOT short-circuit — else SCA-containing runs completed before
        this change under-count forever."""
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("lodash-pro")])
            # Stale v1 cache: count present, no version stamp.
            stale_meta = {"output_summary": "0 findings"}
            self.assertEqual(
                _get_output_summary(run_dir, stale_meta), "1 findings")

    def test_current_version_cache_used(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("lodash-pro")])
            # Current-version cache short-circuits (returns cached, no recompute).
            fresh_meta = {"output_summary": "99 findings", "output_summary_v": 2}
            self.assertEqual(
                _get_output_summary(run_dir, fresh_meta), "99 findings")


class TestPrintFindingsSca(unittest.TestCase):

    def test_sca_helpers(self):
        f = _sca_finding("lodahs")
        self.assertEqual(_sca_finding_package(f), "npm:lodahs")
        self.assertEqual(_sca_finding_kind(f), "Supply Chain · Slopsquat Suspect")

    def test_escalation_helper_extracts_reasons(self):
        f = _sca_finding("react-helper", escalation_reasons=["co-occurs with X"])
        self.assertEqual(_sca_finding_escalations(f), ["co-occurs with X"])
        # Absent / malformed evidence yields an empty list, never raises.
        self.assertEqual(_sca_finding_escalations(_sca_finding("lodahs")), [])
        self.assertEqual(_sca_finding_escalations({}), [])

    def test_escalation_reasons_printed_in_detailed_mode(self):
        rows = [_sca_finding("react-helper", severity="critical",
                             escalation_reasons=["co-occurs with recent_publish"])]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_sca_findings_section(rows, detailed=True)
        self.assertIn("escalated: co-occurs with recent_publish", buf.getvalue())

    def test_escalation_reasons_absent_from_summary_mode(self):
        rows = [_sca_finding("react-helper", severity="critical",
                             escalation_reasons=["co-occurs with recent_publish"])]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_sca_findings_section(rows, detailed=False)
        # Summary table shows the (bumped) severity but not the prose reasons.
        self.assertNotIn("escalated:", buf.getvalue())
        self.assertIn("Critical", buf.getvalue())

    def test_sca_section_renders(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("lodahs")])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _print_findings(_FakeProject([run_dir]))
            out = buf.getvalue()
            self.assertIn("Supply chain / dependencies (SCA)", out)
            self.assertIn("npm:lodahs", out)

    def test_sca_only_run_not_reported_as_no_findings(self):
        """Regression: a run with ONLY sca/findings.json (no top-level
        findings.json) must still surface the SCA section, not print
        'No findings.' and bail."""
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("expresss")])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _print_findings(_FakeProject([run_dir]))
            out = buf.getvalue()
            self.assertNotIn("No findings.", out)
            self.assertIn("npm:expresss", out)

    def test_truly_empty_reports_no_findings(self):
        with TemporaryDirectory() as d:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _print_findings(_FakeProject([Path(d)]))
            self.assertIn("No findings.", buf.getvalue())


class TestProjectFindingsScaE2E(unittest.TestCase):
    """End-to-end across the package boundary: a slopsquat detected by
    the REAL SCA detector + serialised by the REAL write_findings_json
    must surface in /project findings.

    Guards the contract — SCA's on-disk findings.json shape vs the
    project view's loader/renderer. A future SCA serializer change that
    drifts the row shape breaks this test rather than silently dropping
    dependency findings from the project view. Skipped if the optional
    SCA package isn't importable.
    """

    def test_real_slopsquat_surfaces_in_project_findings(self):
        try:
            from packages.sca.parsers.package_json import parse as parse_pkg
            from packages.sca.supply_chain import _slopsquat_to_finding
            from packages.sca.supply_chain.slopsquat import check_dep
            from packages.sca.findings import write_findings_json
        except ImportError:
            self.skipTest("optional SCA package not importable")

        with TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir()
            # 'lodash-pro' = popular prefix 'lodash' + generic suffix
            # 'pro' → the detector's popular_prefix_generic_suffix rule.
            (target / "package.json").write_text(json.dumps({
                "name": "victim-app",
                "dependencies": {"lodash-pro": "^1.0.0", "express": "^4.0.0"},
            }), encoding="utf-8")

            deps = parse_pkg(target / "package.json")
            ss = [f for f in (check_dep(dep) for dep in deps) if f]
            self.assertTrue(ss, "real detector found no slopsquat in 'lodash-pro'")
            sc_findings = [_slopsquat_to_finding(f) for f in ss]

            run_dir = Path(d) / "run"
            write_findings_json(
                run_dir / "sca" / "findings.json",
                supply_chain_findings=sc_findings,
            )

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _print_findings(_FakeProject([run_dir]))
            out = buf.getvalue()
            self.assertIn("Supply chain / dependencies (SCA)", out)
            self.assertIn("lodash-pro", out)
            self.assertIn("Slopsquat", out)


class TestCLI(unittest.TestCase):

    def test_help(self):
        """main() with no args prints help without crashing."""
        with patch("sys.argv", ["raptor-project"]):
            # Should not raise
            main()

    def test_create(self):
        """Create subcommand creates a project file."""
        with TemporaryDirectory() as d:
            output_dir = Path(d) / "output"
            with patch("core.project.cli.ProjectManager") as MockMgr:
                instance = MockMgr.return_value
                instance.create.return_value = type("P", (), {
                    "name": "test", "output_dir": str(output_dir)
                })()
                # The ProjectManager is mocked, so the target is
                # opaque to this CLI parsing test — value just needs
                # to be a string the argparse layer accepts.
                target = str(Path(d) / "code")
                with patch("sys.argv", ["raptor-project", "create", "test",
                                        "--target", target]):
                    main()
                instance.create.assert_called_once()

    def test_list_empty(self):
        """List subcommand with no projects doesn't crash."""
        with patch("core.project.cli.ProjectManager") as MockMgr:
            instance = MockMgr.return_value
            instance.list_projects.return_value = []
            with patch("sys.argv", ["raptor-project", "list"]):
                main()
            instance.list_projects.assert_called_once()


class TestGetActiveProject(unittest.TestCase):
    """Tests for _get_active_project symlink resolution."""

    def test_symlink_resolves(self):
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            (projects_dir / "myapp.json").write_text('{"name":"myapp"}')
            active = projects_dir / ".active"
            active.symlink_to("myapp.json")

            with patch("core.project.project.PROJECTS_DIR", projects_dir):
                with patch.dict(os.environ, {}, clear=True):
                    result = _get_active_project()
            self.assertEqual(result, "myapp")

    def test_dangling_symlink_cleaned(self):
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            active = projects_dir / ".active"
            active.symlink_to("gone.json")

            with patch("core.project.project.PROJECTS_DIR", projects_dir):
                with patch.dict(os.environ, {}, clear=True):
                    result = _get_active_project()
            self.assertIsNone(result)
            self.assertFalse(active.exists() or active.is_symlink())

    def test_no_symlink_returns_none(self):
        with TemporaryDirectory() as d:
            with patch("core.project.project.PROJECTS_DIR", Path(d)):
                with patch.dict(os.environ, {}, clear=True):
                    result = _get_active_project()
            self.assertIsNone(result)



if __name__ == "__main__":
    unittest.main()
