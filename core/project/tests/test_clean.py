"""Tests for project clean — delete old runs, keep latest N."""

import time
import unittest

import pytest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.clean import clean_project
from core.project.project import Project
from core.run import start_run, complete_run


def _make_project_with_runs(tmpdir, run_specs):
    """Create a project with run directories.

    run_specs: list of (command, name) tuples.
    Returns (project, output_dir).
    """
    output_dir = Path(tmpdir) / "project_output"
    output_dir.mkdir()

    for command, name in run_specs:
        run_dir = output_dir / name
        start_run(run_dir, command)
        complete_run(run_dir)
        (run_dir / "findings.json").write_text("[]")
        time.sleep(0.01)  # Ensure different mtimes

    target = str(Path(tmpdir) / "code")
    project = Project(name="test", target=target, output_dir=str(output_dir))
    return project


class TestClean(unittest.TestCase):

    def test_keep_latest_n(self):
        with TemporaryDirectory() as d:
            p = _make_project_with_runs(d, [
                ("scan", "scan-20260401"),
                ("scan", "scan-20260402"),
                ("scan", "scan-20260403"),
                ("scan", "scan-20260404"),
            ])
            stats = clean_project(p, keep=2)
            self.assertEqual(len(stats["kept"]), 2)
            self.assertEqual(len(stats["deleted"]), 2)
            # Newest kept
            self.assertIn("scan-20260404", stats["kept"])
            self.assertIn("scan-20260403", stats["kept"])

    def test_keep_zero_preserves_last_run_per_type(self):
        # --keep 0 is valid (design): delete as aggressively as possible,
        # bounded by the clean-safety floor that never deletes the last run of
        # a command type. The durable coverage store retains deleted verdicts.
        with TemporaryDirectory() as d:
            p = _make_project_with_runs(d, [
                ("scan", "scan-20260401"),
                ("scan", "scan-20260402"),
                ("validate", "validate-20260401"),
            ])
            stats = clean_project(p, keep=0)
            # Newest scan + the sole validate survive; the older scan goes.
            self.assertEqual(len(stats["kept"]), 2)
            self.assertEqual(len(stats["deleted"]), 1)
            self.assertIn("scan-20260402", stats["kept"])
            self.assertIn("validate-20260401", stats["kept"])
            self.assertIn("scan-20260401", stats["deleted"])
            self.assertFalse((p.output_path / "scan-20260401").exists())

    def test_keep_negative_rejected(self):
        with TemporaryDirectory() as d:
            p = _make_project_with_runs(d, [("scan", "scan-20260401")])
            with self.assertRaises(ValueError):
                clean_project(p, keep=-1)

    def test_keep_one_preserves_single_run(self):
        with TemporaryDirectory() as d:
            p = _make_project_with_runs(d, [("scan", "scan-20260401")])
            stats = clean_project(p, keep=1)
            self.assertEqual(len(stats["deleted"]), 0)
            self.assertEqual(len(stats["kept"]), 1)

    def test_per_command_type(self):
        with TemporaryDirectory() as d:
            p = _make_project_with_runs(d, [
                ("scan", "scan-20260401"),
                ("scan", "scan-20260402"),
                ("validate", "validate-20260401"),
                ("validate", "validate-20260402"),
                ("validate", "validate-20260403"),
            ])
            stats = clean_project(p, keep=1)
            self.assertEqual(len(stats["deleted"]), 3)  # 1 scan + 2 validate
            self.assertEqual(len(stats["kept"]), 2)     # 1 scan + 1 validate

    def test_dry_run(self):
        with TemporaryDirectory() as d:
            p = _make_project_with_runs(d, [
                ("scan", "scan-20260401"),
                ("scan", "scan-20260402"),
            ])
            stats = clean_project(p, keep=1, dry_run=True)
            self.assertEqual(len(stats["deleted"]), 1)
            # Directory still exists
            self.assertTrue((p.output_path / "scan-20260401").exists())

    def test_reports_freed_bytes(self):
        with TemporaryDirectory() as d:
            p = _make_project_with_runs(d, [
                ("scan", "scan-20260401"),
                ("scan", "scan-20260402"),
            ])
            # Add some data to the older run
            (p.output_path / "scan-20260401" / "big_file.txt").write_text("x" * 1000)
            stats = clean_project(p, keep=1)
            self.assertGreater(stats["freed_bytes"], 0)

    def test_empty_project(self):
        with TemporaryDirectory() as d:
            output_dir = Path(d) / "empty"
            output_dir.mkdir()
            p = Project(name="test", target=str(Path(d) / "code"),
                        output_dir=str(output_dir))
            stats = clean_project(p, keep=1)
            self.assertEqual(stats["deleted"], [])
            self.assertEqual(stats["kept"], [])

    @pytest.mark.slow
    def test_by_type_breakdown(self):
        with TemporaryDirectory() as d:
            p = _make_project_with_runs(d, [
                ("scan", "scan-20260401"),
                ("scan", "scan-20260402"),
                ("scan", "scan-20260403"),
                ("validate", "validate-20260401"),
                ("validate", "validate-20260402"),
            ])
            from core.project.clean import plan_clean
            plan = plan_clean(p, keep=1)
            self.assertIn("scan", plan["by_type"])
            self.assertIn("validate", plan["by_type"])
            self.assertEqual(plan["by_type"]["scan"]["total"], 3)
            self.assertEqual(plan["by_type"]["scan"]["keep"], 1)
            self.assertEqual(plan["by_type"]["scan"]["delete"], 2)
            self.assertEqual(plan["by_type"]["validate"]["total"], 2)
            self.assertEqual(plan["by_type"]["validate"]["keep"], 1)
            self.assertEqual(plan["by_type"]["validate"]["delete"], 1)


class TestExecuteCleanContainment(unittest.TestCase):
    """Containment is anchored on the caller-supplied project output
    dir — a corrupted plan pointing outside it must be refused."""

    def test_refuses_delete_outside_output_path(self):
        from core.project.clean import execute_clean
        with TemporaryDirectory() as d:
            output = Path(d) / "project_output"
            output.mkdir()
            victim = Path(d) / "unrelated"
            victim.mkdir()
            plan = {"delete_dirs": [victim]}
            with self.assertRaises(RuntimeError):
                execute_clean(plan, output_path=output)
            self.assertTrue(victim.exists())

    def test_deletes_inside_output_path(self):
        from core.project.clean import execute_clean
        with TemporaryDirectory() as d:
            output = Path(d) / "project_output"
            run = output / "scan-1"
            run.mkdir(parents=True)
            execute_clean({"delete_dirs": [run]}, output_path=output)
            self.assertFalse(run.exists())


class TestLiveRunExclusion(unittest.TestCase):
    """Clean/dedup must never plan a live run (running + alive worker)."""

    @staticmethod
    def _mark_running(project, name, tool_pid):
        import json
        meta_path = project.output_path / name / ".raptor-run.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["status"] = "running"
        meta["tool_pid"] = tool_pid
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

    def test_plan_clean_skips_live_run(self):
        import os

        from core.project.clean import plan_clean
        with TemporaryDirectory() as d:
            p = _make_project_with_runs(d, [
                ("scan", "scan-20260401"),
                ("scan", "scan-20260402"),
                ("scan", "scan-20260403"),
            ])
            # Oldest run is live: running + this process's (alive) pid.
            self._mark_running(p, "scan-20260401", os.getpid())
            plan = plan_clean(p, keep=1)
            self.assertIn("scan-20260401", plan["skipped_live"])
            self.assertNotIn("scan-20260401", plan["deleted"])
            self.assertIn("scan-20260401", plan["kept"])
            self.assertIn("scan-20260402", plan["deleted"])

    def test_plan_clean_reclaims_stale_running_run(self):
        # status=running with a DEAD worker is a stale abandon, not a
        # live run — clean may plan it.
        from core.project.clean import plan_clean
        with TemporaryDirectory() as d:
            p = _make_project_with_runs(d, [
                ("scan", "scan-20260401"),
                ("scan", "scan-20260402"),
            ])
            self._mark_running(p, "scan-20260401", -1)
            plan = plan_clean(p, keep=1)
            self.assertEqual(plan["skipped_live"], [])
            self.assertIn("scan-20260401", plan["deleted"])

    def test_plan_dedup_skips_live_run(self):
        import os

        from core.project.clean import plan_dedup
        with TemporaryDirectory() as d:
            p = _make_project_with_runs(d, [
                ("scan", "scan-20260401"),
                ("scan", "scan-20260402"),
            ])
            self._mark_running(p, "scan-20260402", os.getpid())
            plan = plan_dedup(p)
            self.assertIn("scan-20260402", plan["skipped_live"])
            self.assertNotIn("scan-20260402", plan["deleted"])


if __name__ == "__main__":
    unittest.main()
