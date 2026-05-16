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


class TestZipBombEOCDPreflight(unittest.TestCase):
    # EOCD pre-flight rejects over-cap archives BEFORE ZipFile() reads
    # the central directory. Pre-fix the cap only fired AFTER
    # ZipFile.__init__ had already materialised the entire CD into RSS;
    # the in-loop check limited downstream cost but not construction-
    # time memory (Bugbot finding on PR #514).

    def _write_eocd_with_entry_count(self, path: Path, count: int) -> None:
        # Minimal valid-EOCD payload: 4-byte signature, 16 bytes of
        # disk/CD fields with entries-on-disk + total-entries set, then
        # 2-byte comment length = 0. ZipFile won't open this (no central
        # directory) but the EOCD peeker reads the count successfully.
        import struct as _s
        eocd = (
            b"\x50\x4b\x05\x06"
            + _s.pack("<HH", 0, 0)
            + _s.pack("<HH", count, count)
            + _s.pack("<II", 0, 0)
            + _s.pack("<H", 0)
        )
        path.write_bytes(eocd)

    def test_peek_returns_total_entries_for_real_zip(self):
        from core.project.export import _peek_zip_total_entries
        with TemporaryDirectory() as d:
            zpath = Path(d) / "small.zip"
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("a.txt", "hello")
                zf.writestr("b.txt", "world")
            self.assertEqual(_peek_zip_total_entries(zpath), 2)

    def test_peek_returns_none_for_missing_eocd(self):
        from core.project.export import _peek_zip_total_entries
        with TemporaryDirectory() as d:
            zpath = Path(d) / "not-a-zip.bin"
            zpath.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
            self.assertIsNone(_peek_zip_total_entries(zpath))

    def test_peek_reads_synthesized_large_eocd(self):
        from core.project.export import _peek_zip_total_entries
        with TemporaryDirectory() as d:
            zpath = Path(d) / "fake-large.zip"
            self._write_eocd_with_entry_count(zpath, 50_000)
            self.assertEqual(_peek_zip_total_entries(zpath), 50_000)

    def test_validate_zip_contents_rejects_over_cap_before_ZipFile(self):
        # The synthesized file isn't a valid zip; if pre-flight fires,
        # the function returns a zip-bomb-shape warning. If pre-flight
        # missed, ZipFile would return "Invalid zip file" instead.
        with TemporaryDirectory() as d:
            zpath = Path(d) / "over-cap.zip"
            self._write_eocd_with_entry_count(zpath, 50_000)
            safe, warnings = validate_zip_contents(zpath)
            self.assertFalse(safe)
            self.assertTrue(
                any("50000" in w or "zip-bomb shape" in w
                    for w in warnings),
                f"expected zip-bomb-shape rejection, got: {warnings}",
            )
            self.assertFalse(
                any("Invalid zip file" in w for w in warnings),
                "pre-flight should have rejected BEFORE ZipFile() "
                f"opened the file; warnings={warnings}",
            )

    def test_import_project_rejects_over_cap_before_ZipFile(self):
        with TemporaryDirectory() as d:
            zpath = Path(d) / "over-cap.zip"
            self._write_eocd_with_entry_count(zpath, 50_000)
            projects_dir = Path(d) / "projects"
            with self.assertRaises(ValueError) as ctx:
                import_project(zpath, projects_dir)
            self.assertIn("zip-bomb shape", str(ctx.exception))

    def test_peek_handles_short_file_under_22_bytes(self):
        from core.project.export import _peek_zip_total_entries
        with TemporaryDirectory() as d:
            tiny = Path(d) / "tiny.bin"
            tiny.write_bytes(b"PK\x05")
            self.assertIsNone(_peek_zip_total_entries(tiny))


if __name__ == "__main__":
    unittest.main()
