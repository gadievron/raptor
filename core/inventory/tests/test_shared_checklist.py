"""Tests for project-level shared checklist via symlinks."""

import json
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

# core/inventory/tests/test_shared_checklist.py -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.inventory import save_checklist
from core.json import load_json, save_json
from core.run.metadata import _setup_checklist_symlink, _promote_checklist


class TestSaveChecklist(unittest.TestCase):

    def test_saves_to_regular_file(self):
        with TemporaryDirectory() as d:
            data = {"files": [], "total_items": 0}
            save_checklist(d, data)
            loaded = load_json(Path(d) / "checklist.json")
            self.assertEqual(loaded["total_items"], 0)

    def test_saves_through_symlink(self):
        with TemporaryDirectory() as d:
            project_dir = Path(d) / "project"
            run_dir = project_dir / "run-001"
            project_dir.mkdir()
            run_dir.mkdir()

            # Create project-level checklist
            save_json(project_dir / "checklist.json", {"files": [], "version": "old"})

            # Create symlink
            (run_dir / "checklist.json").symlink_to("../checklist.json")

            # Save through symlink
            save_checklist(str(run_dir), {"files": [], "version": "new"})

            # Symlink should still exist
            self.assertTrue((run_dir / "checklist.json").is_symlink())

            # Project-level file should be updated
            loaded = load_json(project_dir / "checklist.json")
            self.assertEqual(loaded["version"], "new")

    def test_symlink_survives_save(self):
        with TemporaryDirectory() as d:
            project_dir = Path(d) / "project"
            run_dir = project_dir / "run-001"
            project_dir.mkdir()
            run_dir.mkdir()

            save_json(project_dir / "checklist.json", {"v": 1})
            (run_dir / "checklist.json").symlink_to("../checklist.json")

            # Multiple saves through symlink
            for i in range(3):
                save_checklist(str(run_dir), {"v": i})

            self.assertTrue((run_dir / "checklist.json").is_symlink())
            loaded = load_json(project_dir / "checklist.json")
            self.assertEqual(loaded["v"], 2)


class TestSetupChecklistSymlink(unittest.TestCase):

    def test_creates_symlink_in_project_mode(self):
        with TemporaryDirectory() as d:
            project_dir = Path(d) / "project"
            run_dir = project_dir / "run-001"
            project_dir.mkdir()
            run_dir.mkdir()

            # Create project JSON and .active symlink
            projects_dir = Path.home() / ".raptor" / "projects"
            projects_dir.mkdir(parents=True, exist_ok=True)
            active_link = projects_dir / ".active"

            # Save/restore state
            old_link = os.readlink(active_link) if active_link.is_symlink() else None

            save_json(projects_dir / "_test_shared.json", {
                "name": "_test_shared",
                "target": "/tmp",
                "output_dir": str(project_dir),
            })
            if active_link.is_symlink() or active_link.exists():
                active_link.unlink()
            active_link.symlink_to("_test_shared.json")

            try:
                _setup_checklist_symlink(run_dir)
                self.assertTrue((run_dir / "checklist.json").is_symlink())
                target = os.readlink(run_dir / "checklist.json")
                self.assertEqual(target, "../checklist.json")
            finally:
                (projects_dir / "_test_shared.json").unlink(missing_ok=True)
                if active_link.is_symlink():
                    active_link.unlink()
                if old_link:
                    active_link.symlink_to(old_link)

    def test_no_symlink_in_standalone_mode(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d) / "run-001"
            run_dir.mkdir()

            # Ensure no active project
            projects_dir = Path.home() / ".raptor" / "projects"
            active_link = projects_dir / ".active"
            old_link = os.readlink(active_link) if active_link.is_symlink() else None
            if active_link.is_symlink():
                active_link.unlink()

            try:
                _setup_checklist_symlink(run_dir)
                self.assertFalse((run_dir / "checklist.json").exists())
            finally:
                if old_link:
                    active_link.symlink_to(old_link)

    def test_skips_existing_real_file(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d) / "run-001"
            run_dir.mkdir()
            (run_dir / "checklist.json").write_text('{"existing": true}')

            # Even if we could detect project mode, existing real file is preserved
            _setup_checklist_symlink(run_dir)
            self.assertFalse((run_dir / "checklist.json").is_symlink())


class TestPromoteChecklist(unittest.TestCase):

    def test_promotes_newest(self):
        with TemporaryDirectory() as d:
            project_dir = Path(d)

            # Create two run dirs with checklists
            run1 = project_dir / "run-001"
            run2 = project_dir / "run-002"
            run1.mkdir()
            run2.mkdir()

            save_json(run1 / "checklist.json", {
                "files": [{"path": "a.py", "items": [
                    {"name": "foo", "kind": "function", "line_start": 1, "checked_by": ["old"]}
                ]}]
            })
            save_json(run2 / "checklist.json", {
                "files": [{"path": "a.py", "items": [
                    {"name": "foo", "kind": "function", "line_start": 1, "checked_by": ["new"]}
                ]}]
            })

            _promote_checklist(project_dir)

            promoted = load_json(project_dir / "checklist.json")
            self.assertIsNotNone(promoted)

    def test_no_checklists_does_nothing(self):
        with TemporaryDirectory() as d:
            _promote_checklist(Path(d))
            self.assertFalse((Path(d) / "checklist.json").exists())

    def test_skips_symlinks(self):
        with TemporaryDirectory() as d:
            project_dir = Path(d)
            run1 = project_dir / "run-001"
            run1.mkdir()
            # Create a symlink (not a real file) — should be skipped
            (run1 / "checklist.json").symlink_to("../nonexistent.json")

            _promote_checklist(project_dir)
            self.assertFalse((project_dir / "checklist.json").exists())


if __name__ == "__main__":
    unittest.main()
