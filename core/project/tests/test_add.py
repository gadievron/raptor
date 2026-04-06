"""Tests for project add and remove operations."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.project import ProjectManager
from core.run import RUN_METADATA_FILE, start_run


class TestAddDirectory(unittest.TestCase):

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        self.mgr = ProjectManager(projects_dir=self.projects_dir)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_add_single_run(self):
        self.mgr.create("myapp", "/tmp/code")
        run_dir = Path(self.tmpdir.name) / "scan-20260406"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("[]")
        added = self.mgr.add_directory("myapp", str(run_dir))
        self.assertEqual(added, 1)

    def test_add_directory_of_runs(self):
        self.mgr.create("myapp", "/tmp/code")
        runs = Path(self.tmpdir.name) / "runs"
        runs.mkdir()
        for name in ["scan_vulns_20260401", "scan_vulns_20260402", "raptor_vulns_20260403"]:
            d = runs / name
            d.mkdir()
            (d / "findings.json").write_text("[]")
        added = self.mgr.add_directory("myapp", str(runs))
        self.assertEqual(added, 3)

    def test_create_on_add(self):
        """Add to non-existent project creates it when --target given."""
        run_dir = Path(self.tmpdir.name) / "scan-20260406"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("[]")
        out = str(Path(self.tmpdir.name) / "new_out")
        added = self.mgr.add_directory("newproject", str(run_dir),
                                        target="/tmp/code", output_dir=out)
        self.assertEqual(added, 1)
        self.assertIsNotNone(self.mgr.load("newproject"))

    def test_create_on_add_requires_target(self):
        run_dir = Path(self.tmpdir.name) / "scan-20260406"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("[]")
        with self.assertRaises(ValueError):
            self.mgr.add_directory("newproject", str(run_dir))

    def test_generates_run_metadata(self):
        self.mgr.create("myapp", "/tmp/code")
        run_dir = Path(self.tmpdir.name) / "scan_vulns_20260406_100000"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("[]")
        self.mgr.add_directory("myapp", str(run_dir))

        p = self.mgr.load("myapp")
        moved_dir = p.output_path / "scan_vulns_20260406_100000"
        self.assertTrue((moved_dir / RUN_METADATA_FILE).exists())

    def test_prefix_inference(self):
        self.mgr.create("myapp", "/tmp/code")
        for name, expected_cmd in [
            ("scan_vulns_20260406", "scan"),
            ("raptor_vulns_20260406", "agentic"),
            ("exploitability-validation-20260406", "validate"),
        ]:
            run_dir = Path(self.tmpdir.name) / name
            run_dir.mkdir()
            (run_dir / "findings.json").write_text("[]")

        runs_parent = Path(self.tmpdir.name)
        # Add all at once — they're in tmpdir alongside projects dir
        # Create a subdirectory with just the runs
        runs = Path(self.tmpdir.name) / "batch"
        runs.mkdir()
        for name in ["scan_vulns_20260406", "raptor_vulns_20260406", "exploitability-validation-20260406"]:
            src = Path(self.tmpdir.name) / name
            if src.exists():
                import shutil
                shutil.move(str(src), str(runs / name))

        self.mgr.add_directory("myapp", str(runs))
        p = self.mgr.load("myapp")
        types = p.get_run_dirs_by_type()
        self.assertIn("scan", types)
        self.assertIn("agentic", types)
        self.assertIn("validate", types)

    def test_skip_non_run_directories(self):
        self.mgr.create("myapp", "/tmp/code")
        runs = Path(self.tmpdir.name) / "mixed"
        runs.mkdir()
        (runs / "scan_20260406").mkdir()
        (runs / "scan_20260406" / "findings.json").write_text("[]")
        (runs / "random_dir").mkdir()  # Not a run directory
        added = self.mgr.add_directory("myapp", str(runs))
        self.assertEqual(added, 1)


class TestRemoveRun(unittest.TestCase):

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        self.mgr = ProjectManager(projects_dir=self.projects_dir)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_remove_to_path(self):
        out = Path(self.tmpdir.name) / "out"
        p = self.mgr.create("myapp", "/tmp/code", output_dir=str(out))
        run_dir = Path(p.output_dir) / "scan-20260406"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("{}")

        to_path = Path(self.tmpdir.name) / "moved"
        self.mgr.remove_run("myapp", "scan-20260406", to_path=str(to_path))
        self.assertFalse(run_dir.exists())
        self.assertTrue((to_path / "scan-20260406" / "findings.json").exists())

    def test_remove_requires_to_path(self):
        self.mgr.create("myapp", "/tmp/code")
        with self.assertRaises(ValueError):
            self.mgr.remove_run("myapp", "scan-20260406")

    def test_remove_missing_run_raises(self):
        self.mgr.create("myapp", "/tmp/code")
        with self.assertRaises(ValueError):
            self.mgr.remove_run("myapp", "nonexistent", to_path="/tmp")


if __name__ == "__main__":
    unittest.main()
