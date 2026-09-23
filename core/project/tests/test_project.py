"""Tests for Project and ProjectManager."""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.project import Project, ProjectManager


class TestProject(unittest.TestCase):

    def setUp(self):
        # Hermetic scratch dir; gives every test a per-instance Path
        # to feed Project(target=...) without hardcoding a host path.
        self._tmp = TemporaryDirectory()
        self.scratch = Path(self._tmp.name)
        # Convention: ``code`` for the project's nominal target,
        # ``other`` if a test needs a second distinct target. Both
        # live under the per-test scratch dir.
        self.target_code = str(self.scratch / "code")
        self.target_other = str(self.scratch / "other")

    def tearDown(self):
        self._tmp.cleanup()

    def test_to_dict_roundtrip(self):
        p = Project(name="test", target=self.target_code, output_dir="out/test",
                    created="2026-04-06", description="desc", notes="notes",
                    threat_model_path="out/test/threat-model.json",
                    threat_model_updated="2026-06-05T08:00:00+00:00")
        d = p.to_dict()
        p2 = Project.from_dict(d)
        self.assertEqual(p.name, p2.name)
        self.assertEqual(p.target, p2.target)
        self.assertEqual(p.description, p2.description)
        self.assertEqual(p.notes, p2.notes)
        self.assertEqual(p.threat_model_path, p2.threat_model_path)
        self.assertEqual(p.threat_model_updated, p2.threat_model_updated)

    def test_legacy_project_defaults_threat_model_fields(self):
        p = Project.from_dict({
            "version": 2,
            "name": "legacy",
            "target": self.target_code,
            "output_dir": "out/legacy",
        })
        from core.project.project import _PROJECT_SCHEMA_VERSION
        self.assertEqual(p.version, _PROJECT_SCHEMA_VERSION)
        self.assertEqual(p.threat_model_path, "")
        self.assertEqual(p.threat_model_updated, "")

    def test_future_version_warns_and_clamps(self):
        with self.assertLogs("core.project.project", level="WARNING") as cm:
            p = Project.from_dict({
                "version": 99,
                "name": "future",
                "target": self.target_code,
                "output_dir": "out/future",
            })
        self.assertEqual(p.version, 99)
        self.assertTrue(any("schema version 99" in msg for msg in cm.output))

    def test_output_path(self):
        p = Project(name="test", target=self.target_code, output_dir="out/projects/test")
        self.assertEqual(p.output_path, Path("out/projects/test"))

    def test_get_run_dirs_empty(self):
        with TemporaryDirectory() as d:
            p = Project(name="test", target=self.target_code, output_dir=d)
            self.assertEqual(p.get_run_dirs(sweep=False), [])

    def test_get_run_dirs_sorted(self):
        with TemporaryDirectory() as d:
            # Create dirs with different mtimes
            (Path(d) / "scan-20260401").mkdir()
            (Path(d) / "scan-20260403").mkdir()
            p = Project(name="test", target=self.target_code, output_dir=d)
            dirs = p.get_run_dirs(sweep=False)
            self.assertEqual(len(dirs), 2)
            # Newest first
            self.assertEqual(dirs[0].name, "scan-20260403")

    def test_get_run_dirs_excludes_internal(self):
        with TemporaryDirectory() as d:
            (Path(d) / "_report").mkdir()
            (Path(d) / ".cache").mkdir()
            (Path(d) / "_tmp").mkdir()
            (Path(d) / "scan-20260401").mkdir()
            p = Project(name="test", target=self.target_code, output_dir=d)
            dirs = p.get_run_dirs(sweep=False)
            self.assertEqual(len(dirs), 1)
            self.assertEqual(dirs[0].name, "scan-20260401")

    def test_annotations_dir_never_a_run(self):
        # The /annotate prose store lives at <output_dir>/annotations:
        # pre-fix run enumeration classified it as an unknown run, so
        # get_run_dirs_by_type stamped machine metadata INSIDE the
        # human notes and /project clean planned it for deletion.
        with TemporaryDirectory() as d:
            ann = Path(d) / "annotations"
            ann.mkdir()
            (ann / "src").mkdir()
            (Path(d) / "scan-20260401").mkdir()
            p = Project(name="test", target=self.target_code, output_dir=d)
            self.assertEqual(
                [r.name for r in p.get_run_dirs(sweep=False)],
                ["scan-20260401"])
            groups = p.get_run_dirs_by_type()
            for dirs in groups.values():
                self.assertNotIn(ann, dirs)
            # No machine metadata stamped inside the notes tree.
            self.assertFalse((ann / ".raptor-run.json").exists())

    def test_sweep_marks_stale_running_as_failed(self):
        """sweep_stale_runs marks 'running' dirs with dead session_pid as failed."""
        from core.json import load_json, save_json
        from core.run.metadata import RUN_METADATA_FILE
        with TemporaryDirectory() as d:
            # Simulate runs from a dead session (PID 99999999)
            for name in ["scan-20260401", "scan-20260402"]:
                run = Path(d) / name
                run.mkdir()
                save_json(run / RUN_METADATA_FILE, {
                    "version": 1, "command": "scan",
                    "timestamp": "2026-04-01T00:00:00+00:00",
                    "status": "running", "extra": {},
                    "session_pid": 99999999,
                })
            p = Project(name="test", target=self.target_code, output_dir=d)
            count = p.sweep_stale_runs(keep_latest=False)
            self.assertEqual(count, 2)
            self.assertEqual(load_json(Path(d) / "scan-20260401" / RUN_METADATA_FILE)["status"], "failed")
            self.assertEqual(load_json(Path(d) / "scan-20260402" / RUN_METADATA_FILE)["status"], "failed")

    def test_sweep_skips_alive_session(self):
        """sweep skips runs whose session PID is still alive."""
        import os

        from core.json import load_json, save_json
        from core.run.metadata import RUN_METADATA_FILE
        with TemporaryDirectory() as d:
            run = Path(d) / "scan-20260401"
            run.mkdir()
            save_json(run / RUN_METADATA_FILE, {
                "version": 1, "command": "scan",
                "timestamp": "2026-04-01T00:00:00+00:00",
                "status": "running", "extra": {},
                "session_pid": os.getpid(),
            })
            # Mock `_pid_alive` to True. Pre-batch 142 the function
            # was a plain `os.kill(pid, 0)` and the test PID itself
            # was sufficient. Post-142 it cross-checks
            # /proc/<pid>/comm for a "claude" substring (PID-reuse
            # protection), and the test process is `python`/`pytest`
            # — fails the comm check. Mock so this test stays
            # focused on sweep logic, not on _pid_alive's mechanics
            # (which has its own coverage).
            p = Project(name="test", target=self.target_code, output_dir=d)
            with patch("core.run.metadata._pid_alive", return_value=True):
                count = p.sweep_stale_runs(keep_latest=False)
            self.assertEqual(count, 0)
            self.assertEqual(load_json(run / RUN_METADATA_FILE)["status"], "running")

    def test_sweep_keep_latest_legacy_runs(self):
        """sweep with keep_latest=True skips newest legacy run (no session_pid)."""
        from core.json import load_json, save_json
        from core.run.metadata import RUN_METADATA_FILE
        with TemporaryDirectory() as d:
            for name, ts in [("scan-20260401", "2026-04-01"), ("scan-20260402", "2026-04-02")]:
                run = Path(d) / name
                run.mkdir()
                save_json(run / RUN_METADATA_FILE, {
                    "version": 1, "command": "scan",
                    "timestamp": f"{ts}T00:00:00+00:00",
                    "status": "running", "extra": {},
                })
            p = Project(name="test", target=self.target_code, output_dir=d)
            count = p.sweep_stale_runs(keep_latest=True)
            self.assertEqual(count, 1)
            self.assertEqual(load_json(Path(d) / "scan-20260401" / RUN_METADATA_FILE)["status"], "failed")
            self.assertEqual(load_json(Path(d) / "scan-20260402" / RUN_METADATA_FILE)["status"], "running")

    def test_sweep_ignores_completed(self):
        """sweep doesn't touch completed/failed dirs."""
        from core.json import load_json
        from core.run.metadata import RUN_METADATA_FILE, complete_run, start_run
        with TemporaryDirectory() as d:
            run1 = Path(d) / "scan-20260401"
            run1.mkdir()
            start_run(run1, "scan")
            complete_run(run1)
            p = Project(name="test", target=self.target_code, output_dir=d)
            count = p.sweep_stale_runs(keep_latest=False)
            self.assertEqual(count, 0)
            self.assertEqual(load_json(run1 / RUN_METADATA_FILE)["status"], "completed")

    def test_get_run_dirs_by_type_jit_metadata(self):
        """Runs without .raptor-run.json get metadata generated on access."""
        with TemporaryDirectory() as d:
            (Path(d) / "scan-20260401").mkdir()
            (Path(d) / "agentic-20260402").mkdir()
            p = Project(name="test", target=self.target_code, output_dir=d)
            groups = p.get_run_dirs_by_type()
            self.assertIn("scan", groups)
            self.assertIn("agentic", groups)
            # Metadata should now exist
            from core.run.metadata import RUN_METADATA_FILE
            self.assertTrue((Path(d) / "scan-20260401" / RUN_METADATA_FILE).exists())
            self.assertTrue((Path(d) / "agentic-20260402" / RUN_METADATA_FILE).exists())


class TestProjectManager(unittest.TestCase):

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        # Isolate the output base. ProjectManager.create() defaults
        # output_dir to the shared repo-relative DEFAULT_OUTPUT_BASE
        # (``out/projects/<name>``) regardless of projects_dir, so under
        # xdist two workers using the same project name race on
        # ``out/projects/myapp`` — one test's purge wipes another's output
        # (surfaced as a flaky test_delete_keeps_output_by_default). Patch
        # the module global to a per-test tmpdir so create() and delete()'s
        # base check both stay isolated.
        out_base = Path(self.tmpdir.name) / "out" / "projects"
        _ob = patch("core.project.project.DEFAULT_OUTPUT_BASE", out_base)
        _ob.start()
        self.addCleanup(_ob.stop)
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        # Per-test scratch targets; the names are stable so listing /
        # rename / find-project-for-target assertions can match
        # without hardcoding a host path. ``target_code`` is the
        # default; siblings (a, b, other) cover the multi-project
        # cases without leaking host /tmp.
        scratch = Path(self.tmpdir.name)
        self.target_code = str(scratch / "code")
        self.target_other = str(scratch / "other")
        self.target_a = str(scratch / "a")
        self.target_b = str(scratch / "b")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_create(self):
        p = self.mgr.create("myapp", self.target_code, description="test app")
        self.assertEqual(p.name, "myapp")
        self.assertEqual(p.description, "test app")
        self.assertTrue((self.projects_dir / "myapp.json").exists())

    def test_create_rejects_traversal_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create("../../etc", self.target_code)

    def test_create_rejects_slash_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create("foo/bar", self.target_code)

    def test_create_rejects_dotfile_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create(".hidden", self.target_code)

    def test_create_rejects_underscore_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create("_report", self.target_code)

    def test_create_rejects_empty_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create("", self.target_code)

    def test_create_rejects_reserved_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create("none", self.target_code)

    def test_create_rejects_reserved_name_case_insensitive(self):
        with self.assertRaises(ValueError):
            self.mgr.create("None", self.target_code)

    def test_create_duplicate_raises(self):
        self.mgr.create("myapp", self.target_code)
        with self.assertRaises(ValueError):
            self.mgr.create("myapp", self.target_code)

    def test_create_custom_output_dir(self):
        out = Path(self.tmpdir.name) / "custom_out"
        p = self.mgr.create("myapp", self.target_code, output_dir=str(out))
        self.assertEqual(p.output_dir, str(out))
        self.assertTrue(out.exists())

    def test_load(self):
        self.mgr.create("myapp", self.target_code, description="loaded")
        p = self.mgr.load("myapp")
        self.assertIsNotNone(p)
        self.assertEqual(p.description, "loaded")

    def test_load_missing(self):
        self.assertIsNone(self.mgr.load("nonexistent"))

    def test_list_projects(self):
        self.mgr.create("a", self.target_a)
        self.mgr.create("b", self.target_b)
        projects = self.mgr.list_projects()
        names = [p.name for p in projects]
        self.assertIn("a", names)
        self.assertIn("b", names)

    def test_list_empty(self):
        self.assertEqual(self.mgr.list_projects(), [])

    def test_delete(self):
        self.mgr.create("myapp", self.target_code)
        self.mgr.delete("myapp")
        self.assertIsNone(self.mgr.load("myapp"))

    def test_delete_keeps_output_by_default(self):
        p = self.mgr.create("myapp", self.target_code)
        output_dir = Path(p.output_dir)
        self.mgr.delete("myapp")
        self.assertTrue(output_dir.exists())

    def test_delete_purge(self):
        p = self.mgr.create("myapp", self.target_code)
        output_dir = Path(p.output_dir)
        self.mgr.delete("myapp", purge=True)
        self.assertFalse(output_dir.exists())

    def test_delete_missing_raises(self):
        with self.assertRaises(ValueError):
            self.mgr.delete("nonexistent")

    def test_rename(self):
        self.mgr.create("old", self.target_code)
        p = self.mgr.rename("old", "new")
        self.assertEqual(p.name, "new")
        self.assertIsNone(self.mgr.load("old"))
        self.assertIsNotNone(self.mgr.load("new"))

    def test_rename_to_existing_raises(self):
        self.mgr.create("a", self.target_a)
        self.mgr.create("b", self.target_b)
        with self.assertRaises(ValueError):
            self.mgr.rename("a", "b")

    def test_rename_validates_new_name(self):
        self.mgr.create("a", self.target_a)
        with self.assertRaises(ValueError):
            self.mgr.rename("a", "none")

    def test_rename_moves_default_output_dir(self):
        p = self.mgr.create("old", self.target_code)
        old_output = Path(p.output_dir)
        (old_output / "scan_1").mkdir(parents=True)
        (old_output / "scan_1" / "findings.json").write_text("[]")
        renamed = self.mgr.rename("old", "new")
        new_output = Path(renamed.output_dir)
        self.assertNotEqual(new_output, old_output)
        self.assertEqual(new_output.name, "new")
        self.assertFalse(old_output.exists())
        self.assertTrue((new_output / "scan_1" / "findings.json").exists())
        # Persisted, not just on the returned object
        self.assertEqual(self.mgr.load("new").output_dir,
                         str(new_output))

    def test_rename_then_recreate_old_name_does_not_share(self):
        # rename A→B once left output_dir at <base>/A; create(A) then
        # minted a SECOND project on the same dir — B's runs showed in
        # A's status and a purge of A destroyed B's runs.
        p = self.mgr.create("appa", self.target_code)
        old_output = Path(p.output_dir)
        (old_output / "scan_1").mkdir(parents=True)
        renamed = self.mgr.rename("appa", "appb")
        recreated = self.mgr.create("appa", self.target_other)
        self.assertNotEqual(recreated.output_dir, renamed.output_dir)
        # The re-created project must not see the renamed project's runs
        self.assertFalse(
            (Path(recreated.output_dir) / "scan_1").exists())

    def test_rename_keeps_custom_output_dir(self):
        custom = Path(self.tmpdir.name) / "custom-out"
        p = self.mgr.create("old", self.target_code,
                            output_dir=str(custom))
        self.mgr.rename("old", "new")
        self.assertEqual(self.mgr.load("new").output_dir, p.output_dir)
        self.assertTrue(custom.exists())

    def test_rename_refuses_existing_destination_dir(self):
        from core.project.project import DEFAULT_OUTPUT_BASE
        p = self.mgr.create("old", self.target_code)
        blocker = DEFAULT_OUTPUT_BASE / "new"
        blocker.mkdir(parents=True)
        with self.assertRaises(ValueError):
            self.mgr.rename("old", "new")
        # Nothing mutated: old project intact, its dir untouched
        self.assertIsNotNone(self.mgr.load("old"))
        self.assertIsNone(self.mgr.load("new"))
        self.assertTrue(Path(p.output_dir).exists())

    def test_rename_force_with_live_runs_keeps_dir(self):
        # A live run's directory must never move under it: the forced
        # rename keeps the old path (and create()'s shared-dir refusal
        # protects a later re-create of the old name).
        from unittest.mock import patch as _patch
        p = self.mgr.create("old", self.target_code)
        live_dir = Path(p.output_dir) / "scan_live"
        live_dir.mkdir(parents=True)
        with _patch("core.project.clean.split_live_runs",
                    return_value=([], [live_dir])):
            renamed = self.mgr.rename("old", "new", force=True)
        self.assertEqual(renamed.output_dir, p.output_dir)
        self.assertTrue(live_dir.exists())
        with self.assertRaises(ValueError):
            self.mgr.create("old", self.target_other)

    def test_create_holds_registry_lock_across_exists_check(self):
        """create() serialises on the registry file: a competing
        create that wins the lock first must make ours fail the
        exists check (no silent last-writer-wins)."""
        import contextlib as _ctx
        from unittest.mock import patch as _patch

        from core.project import project as project_mod

        real_lock = project_mod.project_file_lock

        @_ctx.contextmanager
        def racing_lock(project_file):
            with real_lock(project_file):
                # Simulate the competing create committing while we
                # hold (i.e. before we re-check existence).
                if not project_file.exists():
                    project_file.write_text("{}")
                yield

        with _patch.object(project_mod, "project_file_lock",
                           racing_lock), \
                self.assertRaises(ValueError):
            self.mgr.create("raced", self.target_code)

    def test_create_refuses_claimed_output_dir(self):
        shared = str(Path(self.tmpdir.name) / "shared-out")
        self.mgr.create("a", self.target_a, output_dir=shared)
        with self.assertRaises(ValueError):
            self.mgr.create("b", self.target_b, output_dir=shared)

    def test_create_owner_scan_runs_inside_the_dir_claim(self):
        """The shared-dir owner scan must run INSIDE the output-dir
        claim lock: the name lock is per-NAME, so a competing create of
        a DIFFERENT name with the same dir that wins the claim first
        must be visible to our re-scan."""
        import contextlib as _ctx
        from unittest.mock import patch as _patch

        from core.json import save_json

        shared = str(Path(self.tmpdir.name) / "shared-race")
        real_claim = self.mgr._output_dir_claim_lock

        @_ctx.contextmanager
        def racing_claim(output_dir):
            with real_claim(output_dir):
                # Simulate the competing create (different name, same
                # dir) having committed while holding the claim.
                winner = self.mgr.projects_dir / "winner.json"
                if not winner.exists():
                    save_json(winner, {
                        "name": "winner", "target": self.target_a,
                        "output_dir": str(Path(shared).resolve()),
                        "created": "2026-01-01T00:00:00+00:00",
                    })
                yield

        with _patch.object(self.mgr, "_output_dir_claim_lock",
                           racing_claim), \
                self.assertRaises(ValueError):
            self.mgr.create("loser", self.target_b, output_dir=shared)

    def test_concurrent_creates_different_names_never_share_a_dir(self):
        """Reviewer repro: two concurrent creates of DIFFERENT names
        with the same --output-dir must never both succeed (the
        per-name registry lock alone does not serialise them)."""
        import threading

        for round_no in range(10):
            shared = str(Path(self.tmpdir.name) / f"race-{round_no}")
            barrier = threading.Barrier(2)
            results: dict[str, str] = {}

            def worker(name: str, shared=shared, barrier=barrier,
                       results=results) -> None:
                barrier.wait()
                try:
                    self.mgr.create(name, self.target_a,
                                    output_dir=shared)
                    results[name] = "ok"
                except ValueError:
                    results[name] = "refused"

            names = (f"racer-a-{round_no}", f"racer-b-{round_no}")
            threads = [threading.Thread(target=worker, args=(n,))
                       for n in names]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            oks = [n for n in names if results.get(n) == "ok"]
            self.assertEqual(
                len(oks), 1,
                f"round {round_no}: exactly one create may win a "
                f"shared dir, got {results}")
            owners = [p.name for p in self.mgr.list_projects()
                      if str(Path(p.output_dir).resolve())
                      == str(Path(shared).resolve())]
            self.assertEqual(owners, oks)

    def test_delete_clears_active_symlink(self):
        self.mgr.create("myapp", self.target_code)
        active = self.mgr.projects_dir / ".active"
        active.symlink_to("myapp.json")
        self.mgr.delete("myapp")
        self.assertFalse(active.is_symlink())

    def test_delete_preserves_other_active_symlink(self):
        self.mgr.create("myapp", self.target_code)
        self.mgr.create("other", self.target_other)
        active = self.mgr.projects_dir / ".active"
        active.symlink_to("other.json")
        self.mgr.delete("myapp")
        self.assertTrue(active.is_symlink())

    def test_rename_updates_active_symlink(self):
        self.mgr.create("old", self.target_code)
        active = self.mgr.projects_dir / ".active"
        active.symlink_to("old.json")
        self.mgr.rename("old", "new")
        self.assertEqual(os.readlink(active), "new.json")

    def test_update_notes(self):
        self.mgr.create("myapp", self.target_code)
        p = self.mgr.update_notes("myapp", "new notes")
        self.assertEqual(p.notes, "new notes")
        # Verify persisted
        p2 = self.mgr.load("myapp")
        self.assertEqual(p2.notes, "new notes")

    def test_find_project_for_target(self):
        self.mgr.create("myapp", self.target_code)
        found = self.mgr.find_project_for_target(self.target_code)
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "myapp")

    def test_find_project_for_target_not_found(self):
        self.mgr.create("myapp", self.target_code)
        self.assertIsNone(self.mgr.find_project_for_target(self.target_other))

    def _stamp_content_id(self, project, content_id):
        from core.json import save_json
        Path(project.output_dir).mkdir(parents=True, exist_ok=True)
        save_json(Path(project.output_dir) / "coverage.json",
                  {"version": 1, "content_id": content_id, "files": {}})

    def test_content_id_read_from_store(self):
        p = self.mgr.create("myapp", self.target_code)
        self.assertIsNone(p.content_id)                     # no store yet
        self._stamp_content_id(p, "content:deadbeefcafe0001")
        self.assertEqual(self.mgr.load("myapp").content_id,
                         "content:deadbeefcafe0001")

    def test_find_by_content_id_across_acquisitions(self):
        # A git checkout and a zip extraction of identical source: different
        # target paths, same content id -> resolve to the same project.
        git_p = self.mgr.create("from-git", self.target_a)
        self._stamp_content_id(git_p, "content:abc123")
        found = self.mgr.find_project_for_target(
            self.target_b, content_id="content:abc123")
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "from-git")

    def test_path_match_takes_precedence_over_content(self):
        p = self.mgr.create("myapp", self.target_code)
        self._stamp_content_id(p, "content:abc123")
        # Exact path still matches even when a content_id is supplied.
        found = self.mgr.find_project_for_target(
            self.target_code, content_id="content:nomatch")
        self.assertEqual(found.name, "myapp")

    def test_find_by_content_id_no_match_returns_none(self):
        p = self.mgr.create("myapp", self.target_code)
        self._stamp_content_id(p, "content:abc123")
        self.assertIsNone(
            self.mgr.find_project_for_target(self.target_other,
                                             content_id="content:xyz789"))
        self.assertIsNone(self.mgr.find_project_by_content_id(""))

    def test_remove_run(self):
        p = self.mgr.create("myapp", self.target_code)
        run_dir = Path(p.output_dir) / "scan-20260406"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("{}")

        to_dir = Path(self.tmpdir.name) / "moved"
        self.mgr.remove_run("myapp", "scan-20260406", to_path=str(to_dir))
        self.assertFalse(run_dir.exists())
        self.assertTrue((to_dir / "scan-20260406" / "findings.json").exists())

    def test_remove_run_requires_to_path(self):
        self.mgr.create("myapp", self.target_code)
        with self.assertRaises(ValueError):
            self.mgr.remove_run("myapp", "scan-20260406")


if __name__ == "__main__":
    unittest.main()


class TestThreatModelStampRMW(unittest.TestCase):
    def test_stamp_does_not_clobber_concurrent_trust_write(self):
        # The threat-model actions load a project snapshot BEFORE
        # potentially long work; persisting the whole snapshot at the
        # end re-wrote the trust dict as of load time — a trust
        # marker removed in the meantime silently resurrected (trust
        # markers gate repo-trust witnesses). The RMW mutator reloads
        # under the same lock every other registry mutator uses.
        with TemporaryDirectory() as td:
            mgr = ProjectManager(Path(td) / "projects")
            mgr.create("p1", td, resolve_target=False)
            mgr.set_trust_marker("p1", "config")
            # Simulate the stale-snapshot writer: a concurrent
            # operator removes the marker mid-flight...
            mgr.clear_trust_marker("p1", "config")
            # ...then the threat-model pass stamps its fields.
            mgr.update_threat_model_stamp(
                "p1", updated_at="2026-01-01T00:00:00+00:00",
                path="/x/tm.json",
            )
            fresh = mgr.load("p1")
            self.assertEqual(fresh.threat_model_path, "/x/tm.json")
            self.assertEqual(
                fresh.threat_model_updated, "2026-01-01T00:00:00+00:00")
            self.assertFalse(fresh.trust)  # marker stays removed

    def test_stamp_without_path_keeps_existing_path(self):
        with TemporaryDirectory() as td:
            mgr = ProjectManager(Path(td) / "projects")
            mgr.create("p2", td, resolve_target=False)
            mgr.update_threat_model_stamp(
                "p2", updated_at="t1", path="/x/tm.json")
            mgr.update_threat_model_stamp("p2", updated_at="t2")
            fresh = mgr.load("p2")
            self.assertEqual(fresh.threat_model_path, "/x/tm.json")
            self.assertEqual(fresh.threat_model_updated, "t2")


class TestRegistryMutationLockDiscipline(unittest.TestCase):
    """rename() and delete() must participate in the registry-file RMW
    lock discipline: a locked mutator that loaded before an UNLOCKED
    rename/delete completed would _save() afterwards and resurrect the
    old-name / deleted registry file (duplicate registration over one
    output dir, zombie project). The recorder wraps the real lock so
    the critical-section state is observed at lock release.
    """

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        out_base = Path(self.tmpdir.name) / "out" / "projects"
        _ob = patch("core.project.project.DEFAULT_OUTPUT_BASE", out_base)
        _ob.start()
        self.addCleanup(_ob.stop)
        self.projects_dir = Path(self.tmpdir.name) / "projects"
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.target = str(Path(self.tmpdir.name) / "code")

    def _install_recorder(self):
        import contextlib

        from core.project import project as project_mod
        records = []
        real = project_mod.project_file_lock

        @contextlib.contextmanager
        def _recording(path):
            p = Path(path)
            records.append(("enter", p.name))
            with real(path):
                try:
                    yield
                finally:
                    registry = sorted(
                        f.name for f in self.projects_dir.glob("*.json"))
                    records.append(("exit", p.name, registry))

        patcher = patch.object(
            project_mod, "project_file_lock", _recording)
        patcher.start()
        self.addCleanup(patcher.stop)
        return records

    def test_delete_unlinks_inside_the_registry_lock(self):
        self.mgr.create("myapp", self.target, resolve_target=False)
        records = self._install_recorder()
        self.mgr.delete("myapp")
        self.assertIn(("enter", "myapp.json"), records)
        exits = [r for r in records
                 if r[0] == "exit" and r[1] == "myapp.json"]
        self.assertTrue(exits, "delete released no registry lock")
        # At lock release the file is already gone: a blocked mutator
        # resuming after us loads nothing instead of resurrecting.
        self.assertNotIn("myapp.json", exits[-1][2])

    def test_rename_holds_both_locks_in_sorted_order(self):
        self.mgr.create("beta", self.target, resolve_target=False)
        records = self._install_recorder()
        self.mgr.rename("beta", "alpha")
        enters = [r[1] for r in records if r[0] == "enter"]
        # Both names locked, sorted order (crossing renames can't
        # deadlock), both held before the registry transition.
        self.assertEqual(enters[:2], ["alpha.json", "beta.json"])
        exits = [r for r in records if r[0] == "exit"]
        # The transition is complete at every lock release: new file
        # present, old file gone.
        for _tag, _name, registry in exits[:2]:
            self.assertIn("alpha.json", registry)
            self.assertNotIn("beta.json", registry)

    def test_rename_to_same_name_raises_without_deadlock(self):
        self.mgr.create("same", self.target, resolve_target=False)
        with self.assertRaises(ValueError):
            self.mgr.rename("same", "same")
        self.assertIsNotNone(self.mgr.load("same"))


class TestRenamePinRewriteLocked(unittest.TestCase):
    """The rename marker loop is a read-modify-write on
    .raptor-run.json — it must serialise on the same per-marker
    _metadata_lock every other marker writer takes (complete_run,
    _update_status, write_run_pin). Unlocked, its stale snapshot
    wrote back wholesale and resurrected a run a racing finaliser had
    just completed (status back to running, terminal fields lost) —
    the abandon sweep then fail-stamped the genuinely completed run."""

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        base = Path(self.tmpdir.name)
        self.projects_dir = base / "projects"
        out_base = base / "out" / "projects"
        _ob = patch("core.project.project.DEFAULT_OUTPUT_BASE", out_base)
        _ob.start()
        self.addCleanup(_ob.stop)
        self.mgr = ProjectManager(projects_dir=self.projects_dir)
        self.target = str(base / "code")
        Path(self.target).mkdir()

    def _project_with_pinned_run(self):
        from core.json import save_json
        p = self.mgr.create("old", self.target)
        run = Path(p.output_dir) / "scan-20260101-000000"
        run.mkdir(parents=True)
        save_json(run / ".raptor-run.json", {
            "version": 2, "command": "scan",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "status": "running", "project": "old",
        })
        return run / ".raptor-run.json"

    def test_rewrite_blocks_on_the_marker_lock(self):
        import fcntl
        import os
        import threading
        import time

        marker = self._project_with_pinned_run()
        lock_path = marker.with_suffix(marker.suffix + ".lock")
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)

        done = threading.Event()

        def _rename():
            # force: a status=running marker reads live and this is
            # exactly the supported --force-past-live-runs path the
            # unlocked rewrite raced on. Forced rename keeps the
            # output dir, so the marker path is stable throughout.
            self.mgr.rename("old", "new", force=True)
            done.set()

        moved = marker

        t = threading.Thread(target=_rename, daemon=True)
        t.start()
        try:
            # While a marker writer holds the lock, the rename loop
            # must not have re-pointed the pin (an unlocked rewrite
            # lands within milliseconds).
            deadline = time.monotonic() + 1.0
            from core.json import load_json
            while time.monotonic() < deadline:
                for candidate in (marker, moved):
                    meta = load_json(candidate)
                    if meta is not None:
                        self.assertEqual(
                            meta.get("project"), "old",
                            "pin rewritten while another writer held "
                            "the marker lock — the RMW is not "
                            "serialised")
                if done.is_set():
                    self.fail("rename completed through a held marker lock")
                time.sleep(0.05)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
        t.join(timeout=10)
        self.assertTrue(done.is_set(), "rename never completed")
        from core.json import load_json
        self.assertEqual(load_json(moved).get("project"), "new")

    def test_oversize_marker_left_untouched(self):
        # The loop's read carries the metadata budget: an oversize
        # plant is skipped (with the loud per-dir trail), never
        # parsed wholesale and never rewritten.
        marker = self._project_with_pinned_run()
        payload = ('{"project": "old", "status": "running", "pad": "'
                   + "A" * (2 * 1024 * 1024) + '"}')
        marker.write_text(payload, encoding="utf-8")
        self.mgr.rename("old", "new")
        moved = (Path(str(marker)).parents[2] / "new"
                 / "scan-20260101-000000" / ".raptor-run.json")
        self.assertEqual(moved.read_text(encoding="utf-8"), payload,
                         "oversize marker was parsed and rewritten")

