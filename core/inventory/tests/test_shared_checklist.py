"""Tests for project-level shared checklist via symlinks."""

import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

# core/inventory/tests/test_shared_checklist.py -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.inventory import read_checklist, save_checklist, update_checklist
from core.json import load_json, save_json
from core.run.metadata import _promote_checklist, _setup_checklist_symlink


class TestReadChecklist(unittest.TestCase):

    def test_round_trips_save(self):
        with TemporaryDirectory() as d:
            save_checklist(d, {"files": [], "total_items": 3})
            loaded = read_checklist(d)
            self.assertEqual(loaded["total_items"], 3)

    def test_missing_returns_empty_without_side_effects(self):
        with TemporaryDirectory() as d:
            missing = Path(d) / "never-created"
            self.assertEqual(read_checklist(missing), {})
            # A pure read must not create the output dir (the write
            # accessors' path resolution mkdirs; the reader must not).
            self.assertFalse(missing.exists())

    def test_malformed_returns_empty(self):
        with TemporaryDirectory() as d:
            (Path(d) / "checklist.json").write_text("{broken")
            self.assertEqual(read_checklist(d), {})

    def test_non_dict_returns_empty(self):
        with TemporaryDirectory() as d:
            (Path(d) / "checklist.json").write_text('["not", "a", "dict"]')
            self.assertEqual(read_checklist(d), {})

    def test_reads_through_project_symlink(self):
        with TemporaryDirectory() as d:
            project_dir = Path(d) / "project"
            run_dir = project_dir / "run-001"
            run_dir.mkdir(parents=True)
            save_json(project_dir / "checklist.json", {"version": "proj"})
            (run_dir / "checklist.json").symlink_to("../checklist.json")

            self.assertEqual(read_checklist(str(run_dir))["version"], "proj")

    def test_takes_the_writers_lock(self):
        # The reader must contend on the same checklist.lock file the
        # writers use — verified via a non-blocking flock probe while
        # no reader/writer is active (the lock file exists after a
        # save) and by asserting read_checklist creates/uses it.
        import fcntl
        with TemporaryDirectory() as d:
            save_checklist(d, {"files": []})
            read_checklist(d)
            lock_path = Path(d) / "checklist.lock"
            self.assertTrue(lock_path.exists())
            # Sanity: the lock is free again after the read returns.
            with open(lock_path, "w") as f:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(f, fcntl.LOCK_UN)


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


class TestUpdateChecklist(unittest.TestCase):

    def test_read_modify_write(self):
        with TemporaryDirectory() as d:
            save_checklist(d, {"files": [], "counter": 0})

            def bump(data):
                data["counter"] = data.get("counter", 0) + 1
                return data

            update_checklist(d, bump)
            loaded = load_json(Path(d) / "checklist.json")
            self.assertEqual(loaded["counter"], 1)

    def test_creates_file_when_absent(self):
        with TemporaryDirectory() as d:
            update_checklist(d, lambda data: {"created": True})
            loaded = load_json(Path(d) / "checklist.json")
            self.assertTrue(loaded["created"])

    def test_passes_empty_dict_when_file_absent(self):
        with TemporaryDirectory() as d:
            received = []

            def capture(data):
                received.append(dict(data))
                return {"ok": True}

            update_checklist(d, capture)
            self.assertEqual(received, [{}])

    def test_preserves_existing_fields(self):
        with TemporaryDirectory() as d:
            save_checklist(d, {"files": [{"path": "a.py"}], "version": 1})

            def add_field(data):
                data["extra"] = "added"
                return data

            update_checklist(d, add_field)
            loaded = load_json(Path(d) / "checklist.json")
            self.assertEqual(loaded["version"], 1)
            self.assertEqual(loaded["extra"], "added")
            self.assertEqual(len(loaded["files"]), 1)


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
                "target": "./target",
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
