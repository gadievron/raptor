"""Tests for project export/import with security validation."""

import json
import os
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from core.project.export import export_project, import_project, validate_zip_contents


class TestExportProject(unittest.TestCase):

    def test_creates_zip(self):
        with TemporaryDirectory() as d:
            src = Path(d) / "project"
            src.mkdir()
            (src / "findings.json").write_text('{"id": "test"}')
            dest = Path(d) / "export.zip"
            result = export_project(src, dest)
            self.assertTrue(Path(result["path"]).exists())
            self.assertTrue(zipfile.is_zipfile(result["path"]))
            self.assertEqual(len(result["sha256"]), 64)  # SHA-256 hex length

    def test_zip_contains_files(self):
        with TemporaryDirectory() as d:
            src = Path(d) / "project"
            src.mkdir()
            (src / "findings.json").write_text("{}")
            (src / "report.md").write_text("# Report")
            sub = src / "subdir"
            sub.mkdir()
            (sub / "data.json").write_text("{}")
            dest = Path(d) / "export.zip"
            export_project(src, dest)
            with zipfile.ZipFile(dest) as zf:
                names = zf.namelist()
                self.assertTrue(any("findings.json" in n for n in names))
                self.assertTrue(any("report.md" in n for n in names))


class TestValidateZipContents(unittest.TestCase):

    def test_safe_zip(self):
        with TemporaryDirectory() as d:
            zpath = Path(d) / "safe.zip"
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("findings.json", "{}")
                zf.writestr("subdir/data.json", "{}")
            safe, warnings = validate_zip_contents(zpath)
            self.assertTrue(safe)
            self.assertEqual(warnings, [])

    def test_path_traversal_detected(self):
        with TemporaryDirectory() as d:
            zpath = Path(d) / "evil.zip"
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("../../../etc/passwd", "root:x:0:0")
            safe, warnings = validate_zip_contents(zpath)
            self.assertFalse(safe)
            self.assertTrue(any(".." in w for w in warnings))

    def test_absolute_path_detected(self):
        with TemporaryDirectory() as d:
            zpath = Path(d) / "evil.zip"
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("/etc/passwd", "root:x:0:0")
            safe, warnings = validate_zip_contents(zpath)
            self.assertFalse(safe)
            self.assertTrue(any("absolute" in w.lower() for w in warnings))


class TestImportProject(unittest.TestCase):

    def _make_zip(self, d, name="myproject", include_meta=True):
        """Helper: create a project output dir, export it as zip."""
        src = Path(d) / name
        src.mkdir()
        (src / "findings.json").write_text("{}")
        zpath = Path(d) / "export.zip"
        project_json = None
        if include_meta:
            from core.json import save_json
            project_json = Path(d) / f"{name}.json"
            save_json(project_json, {
                "version": 1, "name": name, "target": "/original/target",
                "output_dir": str(src), "description": "test project",
                "notes": "some notes",
            })
        export_project(src, zpath, project_json_path=project_json)
        return zpath

    def test_basic_import(self):
        with TemporaryDirectory() as d:
            zpath = self._make_zip(d)
            projects_dir = Path(d) / "projects"
            output_base = Path(d) / "output"
            result = import_project(zpath, projects_dir, output_base=output_base)
            self.assertEqual(result["name"], "myproject")
            # Output data extracted
            self.assertTrue((output_base / result["name"] / "findings.json").exists())
            # Project registered
            from core.project import ProjectManager
            mgr = ProjectManager(projects_dir=projects_dir)
            p = mgr.load(result["name"])
            self.assertIsNotNone(p)

    def test_import_restores_metadata(self):
        with TemporaryDirectory() as d:
            zpath = self._make_zip(d, include_meta=True)
            projects_dir = Path(d) / "projects"
            output_base = Path(d) / "output"
            result = import_project(zpath, projects_dir, output_base=output_base)
            from core.project import ProjectManager
            p = ProjectManager(projects_dir=projects_dir).load(result["name"])
            self.assertEqual(p.target, "/original/target")
            self.assertEqual(p.description, "test project")
            self.assertEqual(p.notes, "some notes")
            # output_dir points to local extraction, not original
            self.assertEqual(p.output_dir, str(output_base / result["name"]))

    def test_rejects_existing_name(self):
        with TemporaryDirectory() as d:
            zpath = self._make_zip(d)
            projects_dir = Path(d) / "projects"
            output_base = Path(d) / "output"
            import_project(zpath, projects_dir, output_base=output_base)
            with self.assertRaises(ValueError):
                import_project(zpath, projects_dir, output_base=output_base)

    def test_force_overwrites(self):
        with TemporaryDirectory() as d:
            zpath = self._make_zip(d)
            projects_dir = Path(d) / "projects"
            output_base = Path(d) / "output"
            import_project(zpath, projects_dir, output_base=output_base)
            result = import_project(zpath, projects_dir, output_base=output_base, force=True)
            self.assertTrue((output_base / result["name"] / "findings.json").exists())

    def test_rejects_unsafe_zip(self):
        with TemporaryDirectory() as d:
            zpath = Path(d) / "evil.zip"
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("../../../etc/passwd", "hacked")
            projects_dir = Path(d) / "projects"
            with self.assertRaises(ValueError):
                import_project(zpath, projects_dir)

    def test_rejects_zip_without_metadata(self):
        with TemporaryDirectory() as d:
            zpath = self._make_zip(d, include_meta=False)
            projects_dir = Path(d) / "projects"
            with self.assertRaises(ValueError) as ctx:
                import_project(zpath, projects_dir)
            self.assertIn(".project.json", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
