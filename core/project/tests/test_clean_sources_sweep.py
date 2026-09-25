"""/project clean sweeps unreferenced _sources extraction caches.

Archive-target runs extract into ``<project>/_sources/<name>-<sha>/``
— pre-fix nothing ever reclaimed those trees: cleaning every run that
referenced an archive left its (potentially huge) extraction behind
forever. The sweep is bounded by construction: content-addressed
names only, direct children only, symlinks never, referenced shas
(surviving runs' acquisition stamps + the project's own archive
target) kept, and a start-race grace window on young entries.
"""

import json
import os
import time
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.hash import sha256_file
from core.project.clean import (
    _SOURCES_SWEEP_GRACE_SECONDS,
    plan_sources_sweep,
)
from core.project.project import ProjectManager

_OLD = _SOURCES_SWEEP_GRACE_SECONDS + 600


def _age(p: Path, seconds: int = _OLD) -> None:
    ts = time.time() - seconds
    os.utime(p, (ts, ts))


class SweepFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.projects_dir = self.root / "projects"
        target = self.root / "code"
        target.mkdir()
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.project = self.mgr.create(
            "p", str(target), output_dir=str(self.root / "out"))
        patcher = patch("core.project.project.PROJECTS_DIR",
                        self.projects_dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.sources = Path(self.project.output_dir) / "_sources"
        self.sources.mkdir(parents=True)

    def _entry(self, sha: str, name: str = "app.zip",
               aged: bool = True) -> Path:
        d = self.sources / f"{name}-{sha}"
        d.mkdir()
        (d / "payload.txt").write_text("x" * 128, encoding="utf-8")
        if aged:
            _age(d / "payload.txt")
            _age(d)
        return d

    def _run(self, name: str, sha: str | None) -> Path:
        d = Path(self.project.output_dir) / name
        d.mkdir(parents=True)
        manifest: dict = {}
        if sha is not None:
            manifest["target"] = {
                "source": "archive", "archive_sha256": sha,
                "archive_name": "app.zip", "format": "zip",
            }
        (d / ".raptor-run.json").write_text(json.dumps({
            "project": "p", "project_source": "session",
            "target_path": str(self.sources / f"app.zip-{sha or 'x'}"),
            "manifest": manifest, "status": "completed",
        }), encoding="utf-8")
        return d


class TestPlanSourcesSweep(SweepFixture):
    def test_unreferenced_aged_entry_planned(self):
        entry = self._entry("a" * 64)
        plan = plan_sources_sweep(self.project)
        self.assertEqual(plan["deleted"], [entry.name])
        self.assertGreater(plan["freed_bytes"], 0)

    def test_entry_referenced_by_surviving_run_kept(self):
        sha = "b" * 64
        entry = self._entry(sha)
        self._run("scan-20260925-000000-a", sha)
        plan = plan_sources_sweep(self.project)
        self.assertIn(entry.name, plan["kept"])
        self.assertEqual(plan["deleted"], [])

    def test_entry_referenced_only_by_deleted_run_swept(self):
        sha = "c" * 64
        entry = self._entry(sha)
        victim = self._run("scan-20260925-000000-b", sha)
        plan = plan_sources_sweep(self.project, delete_dirs=[victim])
        self.assertEqual(plan["deleted"], [entry.name])

    def test_young_entry_kept_for_start_race(self):
        entry = self._entry("d" * 64, aged=False)
        plan = plan_sources_sweep(self.project)
        self.assertIn(entry.name, plan["kept"])
        self.assertEqual(plan["deleted"], [])

    def test_non_content_addressed_names_untouched(self):
        stray = self.sources / "notes"
        stray.mkdir()
        _age(stray)
        plan = plan_sources_sweep(self.project)
        self.assertEqual(plan["deleted"], [])
        self.assertNotIn("notes", plan["kept"])  # not even a candidate

    def test_symlink_entry_never_swept(self):
        outside = self.root / "outside"
        outside.mkdir()
        link = self.sources / ("app.zip-" + "e" * 64)
        link.symlink_to(outside)
        plan = plan_sources_sweep(self.project)
        self.assertEqual(plan["deleted"], [])

    def test_project_archive_target_extraction_kept(self):
        archive = self.root / "app.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("a.py", "x = 1\n")
        sha = sha256_file(archive)
        # Point the project at the archive directly on the record.
        proj = self.mgr.load("p")
        proj.target = str(archive)
        self.mgr._save(proj)
        entry = self._entry(sha)
        plan = plan_sources_sweep(self.mgr.load("p"))
        self.assertIn(entry.name, plan["kept"])
        self.assertEqual(plan["deleted"], [])


class TestConfirmGapRefresh(SweepFixture):
    """Review probe P2b: an entry old+unreferenced at PLAN time can be
    re-referenced by a run starting during the operator's unbounded
    confirm wait (a cache HIT doesn't bump mtime) — the executed set
    is re-vetted immediately before deletion."""

    def test_rereferenced_entry_survives_the_executor(self):
        # The probe's exact shape: stale plan handed to the EXECUTOR
        # (not just the CLI wiring) — the re-vet lives in
        # execute_sources_sweep so every caller gets it.
        from core.project.clean import execute_sources_sweep
        sha = "c" * 64
        entry = self._entry(sha)
        plan = plan_sources_sweep(self.project)
        self.assertEqual(plan["deleted"], [entry.name])
        # ... confirm wait: a new run starts and references the sha.
        self._run("scan-20260926-000100-z", sha)
        executed = execute_sources_sweep(self.project, plan)
        self.assertEqual(executed["deleted"], [])
        self.assertEqual(executed["skipped_referenced"], [entry.name])
        self.assertTrue(entry.exists())

    def test_refresh_never_widens_the_confirmed_set(self):
        from core.project.clean import refresh_sources_plan
        plan = plan_sources_sweep(self.project)
        self.assertEqual(plan["deleted"], [])
        # A NEW sweepable entry appearing after the shown plan must
        # not be deleted through the refresh.
        late = self._entry("d" * 64)
        refreshed = refresh_sources_plan(self.project, plan)
        self.assertEqual(refreshed["deleted"], [])
        self.assertTrue(late.exists())

    def test_replan_failure_deletes_nothing(self):
        from core.project.clean import refresh_sources_plan
        entry = self._entry("e" * 64)
        plan = plan_sources_sweep(self.project)
        self.assertEqual(plan["deleted"], [entry.name])
        with patch("core.project.clean.plan_sources_sweep",
                   side_effect=RuntimeError("boom")):
            refreshed = refresh_sources_plan(self.project, plan)
        self.assertEqual(refreshed["deleted"], [])
        self.assertEqual(refreshed["skipped_referenced"], [entry.name])

    def test_do_clean_wiring_survives_the_race(self):
        """End-to-end through _do_clean: the marker lands INSIDE the
        confirm wait, and the entry survives execution."""
        import contextlib
        import io

        from core.project import cli as project_cli
        sha = "f" * 64
        entry = self._entry(sha)

        def racing_confirm(prompt: str) -> bool:
            self._run("scan-20260926-000200-r", sha)
            return True

        buf = io.StringIO()
        with patch.object(project_cli, "_confirm", racing_confirm), \
                contextlib.redirect_stdout(buf):
            project_cli._do_clean(self.project, keep=1,
                                  dry_run=False, yes=False)
        self.assertTrue(entry.exists())
        self.assertIn("re-referenced since plan", buf.getvalue())


class TestExecuteSweep(SweepFixture):
    def test_execute_removes_planned_entries_only(self):
        from core.project.clean import execute_sources_sweep
        doomed = self._entry("a" * 64)
        sha = "b" * 64
        kept = self._entry(sha)
        self._run("scan-20260925-000000-a", sha)
        plan = plan_sources_sweep(self.project)
        executed = execute_sources_sweep(self.project, plan)
        self.assertEqual(executed["deleted"], [doomed.name])
        self.assertFalse(doomed.exists())
        self.assertTrue(kept.exists())


if __name__ == "__main__":
    unittest.main()
