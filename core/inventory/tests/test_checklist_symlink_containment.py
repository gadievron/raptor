"""Containment of the checklist.json symlink slot.

The run lifecycle creates exactly one symlink shape at the checklist
slot: the one-level project link ``../checklist.json``. A target that
can write into the run dir (extraction, fuzz artifacts, hostile repo
content) can replace the slot with a link onto an arbitrary host
file; the write accessors clobber the RESOLVED target via atomic
rename, and the read accessors would launder the victim file into
checklist consumers. Every accessor must refuse an uncontained link.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.inventory import (
    ChecklistPathError,
    checklist_exists,
    ensure_runlocal_checklist,
    iter_checklist_items,
    read_checklist,
    read_checklist_meta,
    save_checklist,
    update_checklist,
)


class TestUncontainedLinkRefused(unittest.TestCase):

    def _planted(self, tmp: Path) -> tuple[Path, Path]:
        """Run dir with checklist.json linked onto a victim file."""
        victim = tmp / "victim.json"
        victim.write_text('{"secret": "host state"}')
        run_dir = tmp / "runs" / "run1"
        run_dir.mkdir(parents=True)
        (run_dir / "checklist.json").symlink_to(victim)
        return run_dir, victim

    def test_save_refuses_and_victim_untouched(self):
        with TemporaryDirectory() as d:
            run_dir, victim = self._planted(Path(d))
            before = victim.read_text()
            with self.assertRaises(ChecklistPathError):
                save_checklist(run_dir, {"files": []})
            self.assertEqual(victim.read_text(), before)
            # No lock file may appear beside the victim either.
            self.assertEqual(
                sorted(p.name for p in Path(d).iterdir()),
                ["runs", "victim.json"],
            )

    def test_read_refuses(self):
        with TemporaryDirectory() as d:
            run_dir, _ = self._planted(Path(d))
            with self.assertRaises(ChecklistPathError):
                read_checklist(run_dir)

    def test_read_meta_refuses(self):
        with TemporaryDirectory() as d:
            run_dir, _ = self._planted(Path(d))
            with self.assertRaises(ChecklistPathError):
                read_checklist_meta(run_dir)

    def test_update_refuses_and_victim_untouched(self):
        with TemporaryDirectory() as d:
            run_dir, victim = self._planted(Path(d))
            before = victim.read_text()
            with self.assertRaises(ChecklistPathError):
                update_checklist(run_dir, lambda c: c)
            self.assertEqual(victim.read_text(), before)

    def test_iter_refuses(self):
        with TemporaryDirectory() as d:
            run_dir, _ = self._planted(Path(d))
            with self.assertRaises(ChecklistPathError):
                list(iter_checklist_items(run_dir))

    def test_exists_reports_absent(self):
        with TemporaryDirectory() as d:
            run_dir, _ = self._planted(Path(d))
            with self.assertLogs("core.inventory", level="WARNING"):
                self.assertFalse(checklist_exists(run_dir))

    def test_sibling_project_slot_refused(self):
        # ``../../other/checklist.json`` is outside the one-level
        # project slot — cross-project redirection is a plant.
        with TemporaryDirectory() as d:
            other = Path(d) / "other"
            other.mkdir()
            (other / "checklist.json").write_text("{}")
            run_dir = Path(d) / "proj" / "run1"
            run_dir.mkdir(parents=True)
            (run_dir / "checklist.json").symlink_to(
                Path("..") / ".." / "other" / "checklist.json")
            with self.assertRaises(ChecklistPathError):
                save_checklist(run_dir, {"files": []})

    def test_runlocal_detach_skips_foreign_lock(self):
        with TemporaryDirectory() as d:
            run_dir, victim = self._planted(Path(d))
            with self.assertLogs("core.inventory", level="WARNING"):
                self.assertTrue(ensure_runlocal_checklist(run_dir))
            self.assertFalse(
                (run_dir / "checklist.json").is_symlink())
            # Detaching must not O_CREAT checklist.lock beside the
            # attacker-chosen target.
            self.assertFalse((victim.parent / "victim.lock").exists())
            self.assertFalse(
                (victim.parent / "checklist.lock").exists())


class TestContainedShapesStillWork(unittest.TestCase):

    def test_standalone_roundtrip_unchanged(self):
        with TemporaryDirectory() as d:
            save_checklist(d, {"files": [], "total_items": 5})
            self.assertEqual(read_checklist(d)["total_items"], 5)
            self.assertTrue(checklist_exists(d))

    def test_project_level_link_still_works(self):
        # The legitimate shape: <project>/runs.../checklist.json ->
        # ../checklist.json (core/run/metadata.py).
        with TemporaryDirectory() as d:
            project = Path(d) / "project"
            run_dir = project / "run1"
            run_dir.mkdir(parents=True)
            (run_dir / "checklist.json").symlink_to("../checklist.json")
            save_checklist(run_dir, {"files": [], "total_items": 7})
            self.assertTrue((project / "checklist.json").is_file())
            self.assertEqual(read_checklist(run_dir)["total_items"], 7)
            self.assertEqual(
                read_checklist_meta(run_dir)["total_items"], 7)
            self.assertTrue(checklist_exists(run_dir))
            update_checklist(
                run_dir,
                lambda c: {**c, "total_items": 8},
            )
            self.assertEqual(read_checklist(run_dir)["total_items"], 8)
            # The link itself survives writes (writes land on the
            # resolved project slot).
            self.assertTrue((run_dir / "checklist.json").is_symlink())

    def test_contained_in_run_link_allowed(self):
        # A link that stays inside the run dir is contained.
        with TemporaryDirectory() as d:
            run_dir = Path(d) / "run1"
            (run_dir / "data").mkdir(parents=True)
            (run_dir / "checklist.json").symlink_to("data/real.json")
            save_checklist(run_dir, {"files": [], "total_items": 2})
            self.assertEqual(read_checklist(run_dir)["total_items"], 2)


if __name__ == "__main__":
    unittest.main()
