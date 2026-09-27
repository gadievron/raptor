"""Tests for project add and remove operations."""

import os
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

    def test_add_regular_file_raises_value_error(self):
        """`project add myproj /path/to/file.json` (an easy operator
        mistake) must produce the CLI's one-line error, not an
        unhandled NotADirectoryError traceback from iterdir()."""
        self.mgr.create("myapp", self.target_code, output_dir=self.output_dir)
        f = Path(self.tmpdir.name) / "findings.json"
        f.write_text("[]")
        with self.assertRaises(ValueError) as ctx:
            self.mgr.add_directory("myapp", str(f))
        self.assertIn("Not a directory", str(ctx.exception))

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


class AdoptionPinRewriteTest(unittest.TestCase):
    """adopt/add/remove rewrite the run pin — the moved dir's governing
    project changes, so its recorded pin must change with it."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        self.output_dir = str(Path(self.tmpdir.name) / "output")
        self.target_code = str(Path(self.tmpdir.name) / "code")
        Path(self.target_code).mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("myapp", self.target_code,
                        output_dir=self.output_dir)

    def _legacy_run(self, name: str) -> Path:
        d = Path(self.tmpdir.name) / name
        d.mkdir()
        (d / "findings.json").write_text("[]")
        from core.json import save_json
        save_json(d / ".raptor-run.json", {
            "version": 2, "command": "scan", "status": "completed",
            "target_path": self.target_code,
        })
        return d

    def test_adopted_run_gets_adopted_pin(self):
        from core.json import load_json
        run = self._legacy_run("scan-legacy1")
        self.assertEqual(self.mgr.add_directory("myapp", str(run)), 1)
        moved = Path(self.output_dir) / "scan-legacy1"
        meta = load_json(moved / ".raptor-run.json")
        self.assertEqual(meta["project"], "myapp")
        self.assertEqual(meta["project_source"], "adopted")
        self.assertEqual(meta["command"], "scan")

    def test_removed_run_pin_cleared(self):
        from core.json import load_json
        run = self._legacy_run("scan-legacy2")
        self.assertEqual(self.mgr.add_directory("myapp", str(run)), 1)
        dest = Path(self.tmpdir.name) / "evicted"
        self.mgr.remove_run("myapp", "scan-legacy2", to_path=str(dest))
        meta = load_json(dest / "scan-legacy2" / ".raptor-run.json")
        self.assertIsNone(meta["project"])
        self.assertEqual(meta["project_source"], "none")


class ProjectMutationGuardTest(unittest.TestCase):
    """Rename pin rewrite, container detection, remove_run traversal,
    delete live-run guard."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        self.output_dir = str(Path(self.tmpdir.name) / "output")
        self.target_code = str(Path(self.tmpdir.name) / "code")
        Path(self.target_code).mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("myapp", self.target_code,
                        output_dir=self.output_dir)

    def _completed_run(self, name: str, project: str = "myapp") -> Path:
        from core.json import save_json
        d = Path(self.output_dir) / name
        d.mkdir(parents=True)
        save_json(d / ".raptor-run.json", {
            "version": 2, "command": "scan", "status": "completed",
            "project": project, "project_source": "session",
            "target_path": self.target_code,
        })
        return d

    def test_rename_repoints_run_pins(self):
        from core.json import load_json
        self._completed_run("scan_1")
        self._completed_run("scan_2")
        self.mgr.rename("myapp", "newname")
        for name in ("scan_1", "scan_2"):
            meta = load_json(
                Path(self.output_dir) / name / ".raptor-run.json")
            self.assertEqual(meta["project"], "newname")

    def test_rename_refuses_live_runs(self):
        from unittest.mock import patch as _patch
        d = self._completed_run("scan_live")
        from core.json import load_json, save_json
        meta = load_json(d / ".raptor-run.json")
        meta["status"] = "running"
        save_json(d / ".raptor-run.json", meta)
        with _patch("core.project.clean.split_live_runs",
                    return_value=([], [d])), \
                self.assertRaises(ValueError):
            self.mgr.rename("myapp", "newname")

    def test_adopting_a_project_dir_takes_the_children(self):
        # A source dir with a top-level checklist.json (every project
        # dir has one) must be treated as a CONTAINER of runs, not
        # swallowed whole as one run.
        from core.json import save_json
        src = Path(self.tmpdir.name) / "oldproj"
        src.mkdir()
        (src / "checklist.json").write_text("{}", encoding="utf-8")
        for name in ("scan_a", "scan_b"):
            d = src / name
            d.mkdir()
            save_json(d / ".raptor-run.json", {
                "version": 2, "command": "scan", "status": "completed",
                "target_path": self.target_code,
            })
        added = self.mgr.add_directory("myapp", str(src))
        self.assertEqual(added, 2)
        self.assertTrue((Path(self.output_dir) / "scan_a").is_dir())
        self.assertFalse(
            (Path(self.output_dir) / "oldproj").exists(),
            "the container itself must not be adopted as a run")

    def test_adopting_the_project_dir_itself_sweeps_children(self):
        # `adopt myapp <the project's own output dir>` used to take
        # the single-run repair path (inside-project match), try to
        # shutil.move the dir into itself, and warn "Cannot move a
        # directory into itself". It must sweep the children instead:
        # correctly-pinned runs are skipped, projectless ones claimed,
        # and no nested <dir>/<dir> is ever created.
        from core.json import load_json, save_json
        self._completed_run("scan_pinned")
        d = Path(self.output_dir) / "scan_orphan"
        d.mkdir(parents=True)
        save_json(d / ".raptor-run.json", {
            "version": 2, "command": "scan", "status": "completed",
            "project": None, "project_source": "argv",
            "target_path": self.target_code,
        })
        added = self.mgr.add_directory("myapp", self.output_dir)
        self.assertEqual(added, 1)
        meta = load_json(d / ".raptor-run.json")
        self.assertEqual(meta["project"], "myapp")
        self.assertFalse(
            (Path(self.output_dir) / Path(self.output_dir).name).exists(),
            "the project dir must never be nested into itself")
        pinned = load_json(
            Path(self.output_dir) / "scan_pinned" / ".raptor-run.json")
        self.assertEqual(pinned["project"], "myapp")

    def test_remove_run_rejects_path_shaped_names(self):
        victim = Path(self.tmpdir.name) / "victim"
        victim.mkdir()
        for bad in ("../victim", "a/b", "..", "."):
            with self.assertRaises(ValueError):
                self.mgr.remove_run("myapp", bad,
                                    to_path=str(Path(self.tmpdir.name) / "o"))
        self.assertTrue(victim.exists())

    def test_delete_without_purge_refuses_live_runs(self):
        from unittest.mock import patch as _patch
        d = self._completed_run("scan_live2")
        with _patch("core.project.clean.split_live_runs",
                    return_value=([], [d])), \
                self.assertRaises(ValueError):
            self.mgr.delete("myapp")


class RenameExternalRunsTest(unittest.TestCase):
    """Rename rewrites external pins + witnesses; URL targets stay
    opaque in the discovery gate."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        self.output_dir = str(Path(self.tmpdir.name) / "output")
        self.target_code = str(Path(self.tmpdir.name) / "code")
        Path(self.target_code).mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("myapp", self.target_code,
                        output_dir=self.output_dir)
        # The ledger writers identity-gate on a claude-shaped comm.
        from unittest.mock import patch as _patch
        from core.project import sessions as _sessions
        p = _patch.object(_sessions, "_comm",
                          lambda pid: "claude" if pid == os.getpid()
                          else None)
        p.start()
        self.addCleanup(p.stop)

    def test_rename_repoints_external_pinned_run(self):
        from core.json import load_json, save_json
        from core.project import sessions
        sessions.record_session("myapp", pid=os.getpid())
        ext = Path(self.tmpdir.name) / "elsewhere" / "scan_x"
        ext.mkdir(parents=True)
        save_json(ext / ".raptor-run.json", {
            "status": "completed", "project": "myapp",
            "project_source": "argv", "target_path": self.target_code,
        })
        sessions.ledger_record_start(ext, pid=os.getpid(),
                                     pin_project="myapp",
                                     record_pin=True)
        sessions.ledger_record_finish(ext, "completed", pid=os.getpid())
        self.mgr.rename("myapp", "renamed")
        meta = load_json(ext / ".raptor-run.json")
        self.assertEqual(meta["project"], "renamed")
        found, project, _src = sessions.ledger_pin_witness(
            ext, pid=os.getpid())
        self.assertTrue(found)
        self.assertEqual(project, "renamed")

    def test_url_recorded_target_never_matches_filesystem(self):
        from core.json import save_json
        from core.orchestration.run_discovery import (
            recorded_target_matches,
        )
        d = Path(self.tmpdir.name) / "web_run"
        d.mkdir()
        save_json(d / ".raptor-run.json", {
            "status": "completed",
            "target_path": "https://evil-unrelated.example/api",
        })
        cwd = os.getcwd()
        try:
            os.chdir(self.target_code)
            self.assertFalse(
                recorded_target_matches(d, self.target_code))
        finally:
            os.chdir(cwd)
        self.assertTrue(recorded_target_matches(
            d, "https://evil-unrelated.example/api"))


class ForceAndRepairTest(unittest.TestCase):
    """rename/remove_run --force overrides for unverifiable-alive
    runs; `project add` re-points a stale pin on an already-present
    run (the rename-crash repair)."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        self.output_dir = str(Path(self.tmpdir.name) / "output")
        self.target_code = str(Path(self.tmpdir.name) / "code")
        Path(self.target_code).mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("myapp", self.target_code,
                        output_dir=self.output_dir)

    def _foreign_running_run(self, name: str) -> Path:
        from core.json import save_json
        d = Path(self.output_dir) / name
        d.mkdir(parents=True)
        save_json(d / ".raptor-run.json", {
            "version": 2, "command": "scan", "status": "running",
            "project": "myapp", "project_source": "session",
            "target_path": self.target_code,
            "session_pid": 12345,
            "session_start": "42",
            "session_boot_id": "00000000-dead-beef-0000-000000000000",
            "session_pidns": "1",
        })
        return d

    def test_rename_force_overrides_unverifiable_live(self):
        self._foreign_running_run("scan_foreign")
        with self.assertRaises(ValueError):
            self.mgr.rename("myapp", "renamed")
        self.mgr.rename("myapp", "renamed", force=True)
        self.assertIsNotNone(self.mgr.load("renamed"))

    def test_remove_run_force_overrides_unverifiable_live(self):
        self._foreign_running_run("scan_foreign2")
        dest = Path(self.tmpdir.name) / "evicted"
        with self.assertRaises(ValueError):
            self.mgr.remove_run("myapp", "scan_foreign2",
                                to_path=str(dest))
        self.mgr.remove_run("myapp", "scan_foreign2",
                            to_path=str(dest), force=True)
        self.assertTrue((dest / "scan_foreign2").is_dir())

    def test_add_repoints_stale_pin_on_present_run(self):
        from core.json import load_json, save_json
        d = Path(self.output_dir) / "scan_stale"
        d.mkdir(parents=True)
        save_json(d / ".raptor-run.json", {
            "version": 2, "command": "scan", "status": "completed",
            "project": "old-ghost", "project_source": "session",
            "target_path": self.target_code,
        })
        # Already present → skipped as an add, but the stale pin
        # (rename crashed between registry move and pin rewrite)
        # must be repaired.
        added = self.mgr.add_directory("myapp", str(d))
        self.assertEqual(added, 0)
        meta = load_json(d / ".raptor-run.json")
        self.assertEqual(meta["project"], "myapp")
        self.assertEqual(meta["project_source"], "adopted")


class AddRepairScopeTest(unittest.TestCase):
    """The add-repair never overrides a pin naming an EXISTING other
    project (that pin is the run's identity). Pins naming MISSING
    projects are repaired in place; PROJECTLESS pins on in-place runs
    are CLAIMED — adopt's documented purpose is retro-creating a
    project around project-less runs, and a run already sitting
    inside the project dir had no other remedy (its trust markers and
    settings never resolved)."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        self.output_dir = str(Path(self.tmpdir.name) / "output")
        self.target_code = str(Path(self.tmpdir.name) / "code")
        Path(self.target_code).mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("myapp", self.target_code,
                        output_dir=self.output_dir)
        self.mgr.create("otherapp", self.target_code,
                        output_dir=str(Path(self.tmpdir.name) / "o2"))

    def _present_run(self, name, project, source="argv"):
        from core.json import save_json
        d = Path(self.output_dir) / name
        d.mkdir(parents=True)
        save_json(d / ".raptor-run.json", {
            "version": 2, "command": "scan", "status": "completed",
            "project": project, "project_source": source,
            "target_path": self.target_code,
        })
        return d

    def test_existing_project_pin_is_not_overridden(self):
        from core.json import load_json
        d = self._present_run("scan_cross", "otherapp")
        self.mgr.add_directory("myapp", str(d))
        meta = load_json(d / ".raptor-run.json")
        self.assertEqual(meta["project"], "otherapp")

    def test_projectless_pin_is_claimed_in_place(self):
        # A run launched via --out into the project path before the
        # project existed (or explicitly projectless) keeps
        # project=null forever — trust markers and settings never
        # resolve for it, and adopt used to skip it silently. The
        # explicit operator adopt claims it: pin rewritten, counted
        # as added (its projections fire for this project).
        from core.json import load_json
        d = self._present_run("scan_none", None, source="none")
        added = self.mgr.add_directory("myapp", str(d))
        self.assertEqual(added, 1)
        meta = load_json(d / ".raptor-run.json")
        self.assertEqual(meta["project"], "myapp")
        self.assertEqual(meta["project_source"], "adopted")

    def test_projectless_argv_pin_is_claimed_in_place(self):
        # project_source="argv" with project=null is the
        # `--project -` shape — the exact pin the screen
        # validate-calib-followup run carried.
        from core.json import load_json
        d = self._present_run("scan_argvnone", None, source="argv")
        added = self.mgr.add_directory("myapp", str(d))
        self.assertEqual(added, 1)
        meta = load_json(d / ".raptor-run.json")
        self.assertEqual(meta["project"], "myapp")

    def test_projectless_foreign_target_is_not_claimed(self):
        # The foreign-target refusal still gates the claim: a
        # null-pinned run recording a DIFFERENT codebase must not
        # enter this project's stores.
        from core.json import load_json, save_json
        d = Path(self.output_dir) / "scan_foreign_null"
        d.mkdir(parents=True)
        other_code = Path(self.tmpdir.name) / "othercode"
        other_code.mkdir()
        save_json(d / ".raptor-run.json", {
            "version": 2, "command": "scan", "status": "completed",
            "project": None, "project_source": "argv",
            "target_path": str(other_code),
        })
        added = self.mgr.add_directory("myapp", str(d))
        self.assertEqual(added, 0)
        meta = load_json(d / ".raptor-run.json")
        self.assertIsNone(meta["project"])

    def test_missing_project_pin_is_repaired(self):
        from core.json import load_json
        d = self._present_run("scan_ghost", "ghost-project")
        self.mgr.add_directory("myapp", str(d))
        meta = load_json(d / ".raptor-run.json")
        self.assertEqual(meta["project"], "myapp")


class MarkerRemnantContainerTest(unittest.TestCase):
    """A run dir whose marker was destroyed (remnant lock file, or
    located inside the project) must never be treated as a CONTAINER —
    container semantics would adopt a planted subdir as a run."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        self.output_dir = str(Path(self.tmpdir.name) / "output")
        self.target_code = str(Path(self.tmpdir.name) / "code")
        Path(self.target_code).mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.mgr.create("victim", self.target_code,
                        output_dir=self.output_dir)

    def _plundered_run(self, base: Path) -> Path:
        run = base / "scan_x"
        plant = run / "afl-out"
        plant.mkdir(parents=True)
        from core.json import save_json
        # marker destroyed; lock remnant survives; planted subdir marker
        (run / ".raptor-run.json.lock").write_text("")
        save_json(plant / ".raptor-run.json", {
            "version": 2, "command": "scan", "status": "completed",
        })
        (plant / "findings.json").write_text("[]")
        return run

    def test_inside_project_repair_never_adopts_the_plant(self):
        run = self._plundered_run(Path(self.output_dir))
        self.mgr.add_directory("victim", str(run))
        self.assertTrue((run / "afl-out").is_dir(),
                        "the plant must stay where it is")
        self.assertFalse(
            (Path(self.output_dir) / "afl-out").exists(),
            "the plant must never be adopted as a run")

    def test_external_remnant_dir_never_adopts_the_plant(self):
        run = self._plundered_run(Path(self.tmpdir.name) / "elsewhere")
        self.mgr.add_directory("victim", str(run))
        self.assertFalse(
            (Path(self.output_dir) / "afl-out").exists(),
            "the plant must never be adopted as a run")

    def test_unprefixed_name_never_reaches_the_child_import(self):
        # A marker-destroyed dir whose NAME fails the lenient run-dir
        # match (adopted --out runs keep operator-chosen names) fell
        # through to the child-import loop and adopted the plant —
        # the inside-project/remnant guards must route it to the
        # single-run path unconditionally.
        run = Path(self.output_dir) / "reuse0001"
        plant = run / "afl-out"
        plant.mkdir(parents=True)
        from core.json import save_json
        (run / ".raptor-run.json.lock").write_text("")
        save_json(plant / ".raptor-run.json", {
            "version": 2, "command": "scan", "status": "completed",
        })
        self.mgr.add_directory("victim", str(run))
        self.assertTrue((run / "afl-out").is_dir())
        self.assertFalse(
            (Path(self.output_dir) / "afl-out").exists(),
            "the plant must never be adopted as a run")
