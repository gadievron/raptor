"""Scope-collision rule: scoped inventory builds never overwrite the
project-level checklist slot."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.inventory import (
    ensure_runlocal_checklist,
    read_checklist,
    save_checklist,
)


def _project_with_linked_run(root: Path) -> tuple[Path, Path]:
    project = root / "proj"
    run = project / "run-001"
    run.mkdir(parents=True)
    save_checklist(project, {"target_path": "/full", "files": [
        {"path": "sub1/a.py", "items": []},
        {"path": "sub2/b.py", "items": []},
    ]})
    (run / "checklist.json").symlink_to("../checklist.json")
    return project, run


class TestEnsureRunlocal(unittest.TestCase):

    def test_detaches_project_symlink(self):
        with TemporaryDirectory() as d:
            project, run = _project_with_linked_run(Path(d))
            before = (project / "checklist.json").read_text()
            with self.assertLogs("core.inventory", level="WARNING") as logs:
                self.assertTrue(ensure_runlocal_checklist(run))
            self.assertIn("DIVERGES", "\n".join(logs.output))
            self.assertFalse((run / "checklist.json").exists())
            self.assertFalse((run / "checklist.json").is_symlink())
            # The project-level inventory is untouched.
            self.assertEqual(
                (project / "checklist.json").read_text(), before)
            # A subsequent save lands run-local, project unchanged.
            save_checklist(run, {"target_path": "/scoped",
                                 "scope": ["sub1"], "files": []})
            self.assertEqual(
                read_checklist(run)["target_path"], "/scoped")
            self.assertEqual(
                read_checklist(project)["target_path"], "/full")

    def test_noop_without_symlink(self):
        with TemporaryDirectory() as d:
            run = Path(d) / "run"
            run.mkdir()
            self.assertFalse(ensure_runlocal_checklist(run))
            save_checklist(run, {"files": []})
            self.assertFalse(ensure_runlocal_checklist(run))
            # The run-local file survives.
            self.assertTrue((run / "checklist.json").is_file())


class TestScopedBuildIsRunLocal(unittest.TestCase):

    def test_build_inventory_scope_never_overwrites_project_slot(self):
        from core.inventory import build_inventory
        with TemporaryDirectory() as d:
            target = Path(d) / "target"
            (target / "sub1").mkdir(parents=True)
            (target / "sub2").mkdir(parents=True)
            (target / "sub1" / "a.py").write_text("def fa():\n    pass\n")
            (target / "sub2" / "b.py").write_text("def fb():\n    pass\n")
            project, run = _project_with_linked_run(Path(d))
            before = (project / "checklist.json").read_text()

            inventory = build_inventory(
                str(target), str(run), scope=["sub1"])

            # The artifact is stamped as partial.
            self.assertEqual(inventory.get("scope"), ["sub1"])
            self.assertEqual(
                [f["path"] for f in inventory["files"]], ["sub1/a.py"])
            # Project-level slot untouched; run slot is a real file.
            self.assertEqual(
                (project / "checklist.json").read_text(), before)
            self.assertFalse((run / "checklist.json").is_symlink())
            self.assertEqual(
                read_checklist(run).get("scope"), ["sub1"])

    def test_unscoped_build_still_writes_through_project_slot(self):
        from core.inventory import build_inventory
        with TemporaryDirectory() as d:
            target = Path(d) / "target"
            (target / "sub1").mkdir(parents=True)
            (target / "sub1" / "a.py").write_text("def fa():\n    pass\n")
            project, run = _project_with_linked_run(Path(d))

            inventory = build_inventory(str(target), str(run))

            self.assertNotIn("scope", inventory)
            # Symlink preserved; the shared slot got the new build.
            self.assertTrue((run / "checklist.json").is_symlink())
            self.assertEqual(
                read_checklist(project)["target_path"], str(target))


class TestPromoteSkipsScoped(unittest.TestCase):

    def test_scoped_run_checklist_never_promoted(self):
        from core.run.metadata import _promote_checklist
        with TemporaryDirectory() as d:
            project = Path(d)
            scoped_run = project / "run-scoped"
            scoped_run.mkdir()
            (scoped_run / "checklist.json").write_text(json.dumps(
                {"target_path": "/t", "scope": ["sub1"],
                 "files": [{"path": "sub1/a.py", "items": []}]}))
            _promote_checklist(project)
            self.assertFalse((project / "checklist.json").exists())

    def test_full_tree_checklist_still_promoted(self):
        from core.run.metadata import _promote_checklist
        with TemporaryDirectory() as d:
            project = Path(d)
            run = project / "run-full"
            run.mkdir()
            (run / "checklist.json").write_text(json.dumps(
                {"target_path": "/t",
                 "files": [{"path": "a.py", "items": []}]}))
            _promote_checklist(project)
            self.assertTrue((project / "checklist.json").is_file())


class TestSymlinkSetupSkipsShardedRunLocal(unittest.TestCase):

    def test_no_symlink_over_runlocal_sharded_checklist(self):
        # A run-local sharded checklist occupies the slot; the
        # project-mode symlink must not shadow it.
        import core.run.metadata as md
        with TemporaryDirectory() as d:
            project = Path(d) / "proj"
            run = project / "run-001"
            shard_dir = run / "checklist"
            shard_dir.mkdir(parents=True)
            (shard_dir / "index.json").write_text(
                json.dumps({"schema_version": 1, "meta": {},
                            "shards": []}))
            save_checklist(project, {"files": []})

            class _Pin:
                @staticmethod
                def pin_project_dir(_run):
                    return project

            # Drive the guard directly: pin resolution is exercised
            # elsewhere; here only the slot checks matter.
            orig = md._setup_checklist_symlink
            import core.run.pin as pin_mod
            real_pin = pin_mod.pin_project_dir
            pin_mod.pin_project_dir = _Pin.pin_project_dir
            try:
                orig(run, target=None)
            finally:
                pin_mod.pin_project_dir = real_pin
            self.assertFalse((run / "checklist.json").exists())
            self.assertFalse((run / "checklist.json").is_symlink())


if __name__ == "__main__":
    unittest.main()
