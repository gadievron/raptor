"""Import transaction safety: staged extraction, atomic publish,
and collision handling against unregistered same-name directories.

Pre-fix, ``import_project`` extracted straight into
``output_base/<name>`` with ``mkdir(exist_ok=True)`` and checked
collisions only against the project registry:

* a same-name UNREGISTERED orphan dir was silently merged into, and
  any late failure ``rmtree``'d it — destroying data import never
  created;
* with ``--force`` the old project tree (and its registration) was
  deleted BEFORE extraction even started, so a failed import lost
  the previous data with no rollback.

Post-fix, extraction goes to a fresh ``.import-<name>-*`` staging
dir, trust passes run on the staged tree, and only then is the tree
atomically renamed into place; failure cleanup removes the staging
dir only.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from core.project.export import export_project, import_project
from core.project.project import ProjectManager


def _make_archive(d: Path, name: str = "myproj") -> Path:
    """Build a small valid project archive under *d* and return its path."""
    src = d / "build-src" / name
    (src / "run_20260101-000000").mkdir(parents=True)
    (src / "run_20260101-000000" / "findings.json").write_text(
        '{"findings": []}')
    (src / "notes.txt").write_text("archive payload")
    zip_path = d / f"{name}.zip"
    project_json = d / f"{name}.json"
    project_json.write_text(json.dumps({
        "name": name,
        "target": str(d / "fake-target"),
        "output_dir": str(src),
    }))
    export_project(src, zip_path, project_json_path=project_json)
    return zip_path


class TestUnregisteredCollision(unittest.TestCase):
    def test_refuses_unregistered_same_name_dir(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            zip_path = _make_archive(d)
            projects_dir = d / "projects"
            output_base = d / "out"
            orphan = output_base / "myproj"
            orphan.mkdir(parents=True)
            sentinel = orphan / "operator-data.txt"
            sentinel.write_text("do not touch")

            with self.assertRaises(ValueError) as cm:
                import_project(zip_path, projects_dir,
                               output_base=output_base)
            self.assertIn("no project", str(cm.exception).lower())
            self.assertIn("registered", str(cm.exception).lower())
            # The orphan is untouched — no merge, no deletion.
            self.assertTrue(sentinel.exists())
            self.assertEqual(sentinel.read_text(), "do not touch")
            self.assertFalse((orphan / "notes.txt").exists())
            # Nothing got registered.
            mgr = ProjectManager(projects_dir=projects_dir)
            self.assertIsNone(mgr.load("myproj"))
            # No staging leftovers.
            self.assertEqual(list(output_base.glob(".import-*")), [])

    def test_force_replaces_unregistered_dir_wholesale(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            zip_path = _make_archive(d)
            projects_dir = d / "projects"
            output_base = d / "out"
            orphan = output_base / "myproj"
            orphan.mkdir(parents=True)
            (orphan / "stale.txt").write_text("old debris")

            result = import_project(zip_path, projects_dir, force=True,
                                    output_base=output_base)
            imported = Path(result["output_dir"])
            # Replaced, never merged: debris gone, payload present.
            self.assertFalse((imported / "stale.txt").exists())
            self.assertEqual((imported / "notes.txt").read_text(),
                             "archive payload")
            self.assertEqual(list(output_base.glob(".import-*")), [])


class TestFailureRollback(unittest.TestCase):
    def test_failed_force_reimport_preserves_existing_project(self):
        """A mid-import failure (after extraction, during the
        annotation-demotion pass) must leave the previously imported
        project's data AND registration intact."""
        with TemporaryDirectory() as td:
            d = Path(td)
            zip_path = _make_archive(d)
            projects_dir = d / "projects"
            output_base = d / "out"

            first = import_project(zip_path, projects_dir,
                                   output_base=output_base)
            old_dir = Path(first["output_dir"])
            self.assertTrue((old_dir / "notes.txt").exists())

            with mock.patch(
                "core.project.export._demote_imported_annotations",
                side_effect=RuntimeError("boom"),
            ):
                with self.assertRaises(ValueError):
                    import_project(zip_path, projects_dir, force=True,
                                   output_base=output_base)

            # Old data survives the failed re-import.
            self.assertTrue((old_dir / "notes.txt").exists())
            # Registration survives too.
            mgr = ProjectManager(projects_dir=projects_dir)
            self.assertIsNotNone(mgr.load("myproj"))
            # Failure cleanup removed only the staging dir.
            self.assertEqual(list(output_base.glob(".import-*")), [])

    def test_mid_extract_failure_cleans_only_staging(self):
        """A failure inside the extraction loop removes the staging
        dir and nothing else under the output base."""
        with TemporaryDirectory() as td:
            d = Path(td)
            zip_path = _make_archive(d)
            projects_dir = d / "projects"
            output_base = d / "out"
            bystander = output_base / "other-project"
            bystander.mkdir(parents=True)
            (bystander / "keep.txt").write_text("keep")

            with mock.patch(
                "core.project.export._demote_imported_annotations",
                side_effect=RuntimeError("boom"),
            ):
                with self.assertRaises(ValueError):
                    import_project(zip_path, projects_dir,
                                   output_base=output_base)

            self.assertTrue((bystander / "keep.txt").exists())
            self.assertFalse((output_base / "myproj").exists())
            self.assertEqual(list(output_base.glob(".import-*")), [])


class TestSuccessfulImportShape(unittest.TestCase):
    def test_publish_is_rename_of_staging(self):
        with TemporaryDirectory() as td:
            d = Path(td)
            zip_path = _make_archive(d)
            projects_dir = d / "projects"
            output_base = d / "out"
            result = import_project(zip_path, projects_dir,
                                    output_base=output_base)
            imported = Path(result["output_dir"])
            self.assertEqual(imported, output_base / "myproj")
            self.assertEqual((imported / "notes.txt").read_text(),
                             "archive payload")
            self.assertTrue(
                (imported / "run_20260101-000000" / "findings.json").exists()
            )
            self.assertEqual(list(output_base.glob(".import-*")), [])


if __name__ == "__main__":
    unittest.main()
