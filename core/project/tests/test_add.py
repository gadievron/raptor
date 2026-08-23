"""Tests for project add and remove operations."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.project import ProjectManager
from core.run import RUN_METADATA_FILE


class TestAddDirectory(unittest.TestCase):

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        self.output_dir = str(Path(self.tmpdir.name) / "output")
        # Per-test scratch target; lives under the same tmpdir, so no
        # hardcoded host path leaks into Project(target=...) values.
        self.target_code = str(Path(self.tmpdir.name) / "code")
        self.mgr = ProjectManager(projects_dir=self.projects_dir)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_add_single_run(self):
        self.mgr.create("myapp", self.target_code, output_dir=self.output_dir)
        run_dir = Path(self.tmpdir.name) / "scan-20260406"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("[]")
        added = self.mgr.add_directory("myapp", str(run_dir))
        self.assertEqual(added, 1)

    def test_add_directory_of_runs(self):
        self.mgr.create("myapp", self.target_code, output_dir=self.output_dir)
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
                                        target=self.target_code, output_dir=out)
        self.assertEqual(added, 1)
        self.assertIsNotNone(self.mgr.load("newproject"))

    def test_create_on_add_requires_target(self):
        run_dir = Path(self.tmpdir.name) / "scan-20260406"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("[]")
        with self.assertRaises(ValueError):
            self.mgr.add_directory("newproject", str(run_dir))

    def test_generates_run_metadata(self):
        self.mgr.create("myapp", self.target_code, output_dir=self.output_dir)
        run_dir = Path(self.tmpdir.name) / "scan_vulns_20260406_100000"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("[]")
        self.mgr.add_directory("myapp", str(run_dir))

        p = self.mgr.load("myapp")
        moved_dir = p.output_path / "scan_vulns_20260406_100000"
        self.assertTrue((moved_dir / RUN_METADATA_FILE).exists())

    def test_prefix_inference(self):
        self.mgr.create("myapp", self.target_code, output_dir=self.output_dir)
        for name, expected_cmd in [
            ("scan_vulns_20260406", "scan"),
            ("raptor_vulns_20260406", "agentic"),
            ("exploitability-validation-20260406", "validate"),
        ]:
            run_dir = Path(self.tmpdir.name) / name
            run_dir.mkdir()
            (run_dir / "findings.json").write_text("[]")

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
        self.mgr.create("myapp", self.target_code, output_dir=self.output_dir)
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
        # Isolate the output base: two tests here call create("myapp")
        # without an explicit output_dir, which defaults to the shared
        # repo-relative DEFAULT_OUTPUT_BASE (``out/projects/myapp``). Patch
        # it to a per-test tmpdir so they don't write to / race on the
        # shared path under xdist. (See test_project.py for the full race.)
        out_base = Path(self.tmpdir.name) / "out" / "projects"
        _ob = patch("core.project.project.DEFAULT_OUTPUT_BASE", out_base)
        _ob.start()
        self.addCleanup(_ob.stop)
        # Per-test scratch target; lives under the same tmpdir, so no
        # hardcoded host path leaks into Project(target=...) values.
        self.target_code = str(Path(self.tmpdir.name) / "code")
        self.mgr = ProjectManager(projects_dir=self.projects_dir)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_remove_to_path(self):
        out = Path(self.tmpdir.name) / "out"
        p = self.mgr.create("myapp", self.target_code, output_dir=str(out))
        run_dir = Path(p.output_dir) / "scan-20260406"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("{}")

        to_path = Path(self.tmpdir.name) / "moved"
        self.mgr.remove_run("myapp", "scan-20260406", to_path=str(to_path))
        self.assertFalse(run_dir.exists())
        self.assertTrue((to_path / "scan-20260406" / "findings.json").exists())

    def test_remove_requires_to_path(self):
        self.mgr.create("myapp", self.target_code)
        with self.assertRaises(ValueError):
            self.mgr.remove_run("myapp", "scan-20260406")

    def test_remove_missing_run_raises(self):
        self.mgr.create("myapp", self.target_code)
        with self.assertRaises(ValueError):
            self.mgr.remove_run("myapp", "nonexistent",
                                to_path=str(Path(self.tmpdir.name) / "elsewhere"))


if __name__ == "__main__":
    unittest.main()


class TestAdoptionProjections(unittest.TestCase):
    """Adopted runs must become VISIBLE: target-mismatched runs are
    refused, and an adopted run's journal reaches the project index
    (the completion-time merge already fired before adoption)."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        self.output_dir = str(Path(self.tmpdir.name) / "output")
        self.target_code = str(Path(self.tmpdir.name) / "code")
        Path(self.target_code).mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _run_with_journal(self, name, target=None):
        import json as _json
        run_dir = Path(self.tmpdir.name) / name
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("[]")
        meta = {"version": 2, "command": "audit", "status": "completed",
                "timestamp": "2026-01-01T00:00:00+00:00"}
        if target:
            meta["target_path"] = target
        (run_dir / RUN_METADATA_FILE).write_text(_json.dumps(meta))
        from core.coverage.journal import (
            ReviewJournalEntry,
            append_entry,
            now_iso,
        )
        append_entry(run_dir, ReviewJournalEntry(
            ts=now_iso(), run_id=name, file="a.c", function="f",
            verdict="clean", source_hash="ab12", line_start=1, line_end=3,
        ))
        return run_dir

    def test_adopted_run_journal_reaches_project_index(self):
        self.mgr.create("myapp", self.target_code, output_dir=self.output_dir)
        run_dir = self._run_with_journal(
            "audit_20260101_000000", target=self.target_code)
        added = self.mgr.add_directory("myapp", str(run_dir))
        self.assertEqual(added, 1)
        from core.coverage.journal import load_index
        project = self.mgr.load("myapp")
        idx = load_index(project.output_path)
        self.assertIn("a.c:f", idx)
        self.assertEqual(idx["a.c:f"].verdict, "clean")

    def test_foreign_target_run_refused(self):
        self.mgr.create("myapp", self.target_code, output_dir=self.output_dir)
        other = Path(self.tmpdir.name) / "othercode"
        other.mkdir()
        run_dir = self._run_with_journal(
            "audit_20260101_000001", target=str(other))
        added = self.mgr.add_directory("myapp", str(run_dir))
        self.assertEqual(added, 0)
        self.assertTrue(run_dir.exists(), "refused run must stay in place")

    def test_metadata_less_run_still_adoptable(self):
        self.mgr.create("myapp", self.target_code, output_dir=self.output_dir)
        run_dir = Path(self.tmpdir.name) / "scan-legacy"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("[]")
        self.assertEqual(self.mgr.add_directory("myapp", str(run_dir)), 1)

    def test_adopt_target_inference(self):
        run_dir = self._run_with_journal(
            "audit_20260101_000002", target=self.target_code)
        inferred = self.mgr.adopt_target_for(str(run_dir))
        self.assertEqual(str(Path(self.target_code).resolve()), inferred)

    def test_adoption_builds_checklist_and_snapshots_coverage(self):
        """A fresh retro-created project has no checklist.json, so the
        coverage snapshot no-ops and the adopted run's review history
        never reaches the durable store. Adoption must build the
        project checklist from the target and re-run the projections
        so the journal-derived coverage lands in coverage.json."""
        (Path(self.target_code) / "a.py").write_text(
            "def f():\n    return 1\n")
        self.mgr.create("myapp", self.target_code,
                        output_dir=self.output_dir)
        run_dir = self._run_with_journal(
            "audit_20260101_000003", target=self.target_code)
        # Journal the function the target actually contains, so the
        # store import can anchor it to an inventory line range.
        from core.coverage.journal import (
            ReviewJournalEntry,
            append_entry,
            now_iso,
        )
        append_entry(run_dir, ReviewJournalEntry(
            ts=now_iso(), run_id="audit_20260101_000003",
            file="a.py", function="f", verdict="clean",
            source_hash="cd34", line_start=1, line_end=2,
        ))

        self.assertEqual(self.mgr.add_directory("myapp", str(run_dir)), 1)

        project = self.mgr.load("myapp")
        checklist_path = project.output_path / "checklist.json"
        self.assertTrue(checklist_path.exists(),
                        "adoption must build the project checklist")
        cov_path = project.output_path / "coverage.json"
        self.assertTrue(cov_path.exists(),
                        "adopted coverage must reach the durable store")
        from core.coverage.store import CoverageStore
        store = CoverageStore(cov_path)
        tools = store.tool_coverage_of_range("a.py", 1, 2)
        self.assertIn("audit", tools,
                      "journal-derived review must be in the store")

    def test_adoption_checklist_noop_when_target_missing(self):
        """Target deleted since the runs completed: adoption still
        succeeds, no checklist is fabricated, nothing raises."""
        gone = str(Path(self.tmpdir.name) / "gone")
        self.mgr.create("ghost", gone, output_dir=str(
            Path(self.tmpdir.name) / "ghost_out"))
        run_dir = self._run_with_journal(
            "audit_20260101_000004", target=gone)
        self.assertEqual(self.mgr.add_directory("ghost", str(run_dir)), 1)
        project = self.mgr.load("ghost")
        self.assertFalse((project.output_path / "checklist.json").exists())

    def test_adoption_leaves_existing_checklist_alone(self):
        """A project that already has a checklist keeps it byte-for-byte;
        the snapshot fires through the normal projection path."""
        import json as _json
        (Path(self.target_code) / "a.py").write_text(
            "def f():\n    return 1\n")
        self.mgr.create("myapp", self.target_code,
                        output_dir=self.output_dir)
        project = self.mgr.load("myapp")
        existing = {"files": [{"path": "a.py", "items": [
            {"name": "f", "line_start": 1, "line_end": 2}]}]}
        checklist_path = project.output_path / "checklist.json"
        checklist_path.write_text(_json.dumps(existing))
        run_dir = self._run_with_journal(
            "audit_20260101_000005", target=self.target_code)
        self.assertEqual(self.mgr.add_directory("myapp", str(run_dir)), 1)
        self.assertEqual(_json.loads(checklist_path.read_text()), existing)
