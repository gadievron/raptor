"""Tests for Project and ProjectManager."""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.project import Project, ProjectManager


class TestProject(unittest.TestCase):

    def test_to_dict_roundtrip(self):
        p = Project(name="test", target="/tmp/code", output_dir="out/test",
                    created="2026-04-06", description="desc", notes="notes")
        d = p.to_dict()
        p2 = Project.from_dict(d)
        self.assertEqual(p.name, p2.name)
        self.assertEqual(p.target, p2.target)
        self.assertEqual(p.description, p2.description)
        self.assertEqual(p.notes, p2.notes)

    def test_output_path(self):
        p = Project(name="test", target="/tmp", output_dir="out/projects/test")
        self.assertEqual(p.output_path, Path("out/projects/test"))

    def test_get_run_dirs_empty(self):
        with TemporaryDirectory() as d:
            p = Project(name="test", target="/tmp", output_dir=d)
            self.assertEqual(p.get_run_dirs(), [])

    def test_get_run_dirs_sorted(self):
        with TemporaryDirectory() as d:
            # Create dirs with different mtimes
            (Path(d) / "scan-20260401").mkdir()
            (Path(d) / "scan-20260403").mkdir()
            p = Project(name="test", target="/tmp", output_dir=d)
            dirs = p.get_run_dirs()
            self.assertEqual(len(dirs), 2)
            # Newest first
            self.assertEqual(dirs[0].name, "scan-20260403")

    def test_get_run_dirs_excludes_internal(self):
        with TemporaryDirectory() as d:
            (Path(d) / "_report").mkdir()
            (Path(d) / ".cache").mkdir()
            (Path(d) / "_tmp").mkdir()
            (Path(d) / "scan-20260401").mkdir()
            p = Project(name="test", target="/tmp", output_dir=d)
            dirs = p.get_run_dirs()
            self.assertEqual(len(dirs), 1)
            self.assertEqual(dirs[0].name, "scan-20260401")

    def test_get_run_dirs_by_type_jit_metadata(self):
        """Runs without .raptor-run.json get metadata generated on access."""
        with TemporaryDirectory() as d:
            (Path(d) / "scan-20260401").mkdir()
            (Path(d) / "agentic-20260402").mkdir()
            p = Project(name="test", target="/tmp", output_dir=d)
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
        self.mgr = ProjectManager(projects_dir=self.projects_dir)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_create(self):
        p = self.mgr.create("myapp", "/tmp/code", description="test app")
        self.assertEqual(p.name, "myapp")
        self.assertEqual(p.description, "test app")
        self.assertTrue((self.projects_dir / "myapp.json").exists())

    def test_create_rejects_traversal_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create("../../etc", "/tmp/code")

    def test_create_rejects_slash_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create("foo/bar", "/tmp/code")

    def test_create_rejects_dotfile_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create(".hidden", "/tmp/code")

    def test_create_rejects_underscore_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create("_report", "/tmp/code")

    def test_create_rejects_empty_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create("", "/tmp/code")

    def test_create_rejects_reserved_name(self):
        with self.assertRaises(ValueError):
            self.mgr.create("none", "/tmp/code")

    def test_create_rejects_reserved_name_case_insensitive(self):
        with self.assertRaises(ValueError):
            self.mgr.create("None", "/tmp/code")

    def test_create_duplicate_raises(self):
        self.mgr.create("myapp", "/tmp/code")
        with self.assertRaises(ValueError):
            self.mgr.create("myapp", "/tmp/code")

    def test_create_custom_output_dir(self):
        out = Path(self.tmpdir.name) / "custom_out"
        p = self.mgr.create("myapp", "/tmp/code", output_dir=str(out))
        self.assertEqual(p.output_dir, str(out))
        self.assertTrue(out.exists())

    def test_load(self):
        self.mgr.create("myapp", "/tmp/code", description="loaded")
        p = self.mgr.load("myapp")
        self.assertIsNotNone(p)
        self.assertEqual(p.description, "loaded")

    def test_load_missing(self):
        self.assertIsNone(self.mgr.load("nonexistent"))

    def test_list_projects(self):
        self.mgr.create("a", "/tmp/a")
        self.mgr.create("b", "/tmp/b")
        projects = self.mgr.list_projects()
        names = [p.name for p in projects]
        self.assertIn("a", names)
        self.assertIn("b", names)

    def test_list_empty(self):
        self.assertEqual(self.mgr.list_projects(), [])

    def test_delete(self):
        self.mgr.create("myapp", "/tmp/code")
        self.mgr.delete("myapp")
        self.assertIsNone(self.mgr.load("myapp"))

    def test_delete_keeps_output_by_default(self):
        p = self.mgr.create("myapp", "/tmp/code")
        output_dir = Path(p.output_dir)
        self.mgr.delete("myapp")
        self.assertTrue(output_dir.exists())

    def test_delete_purge(self):
        p = self.mgr.create("myapp", "/tmp/code")
        output_dir = Path(p.output_dir)
        self.mgr.delete("myapp", purge=True)
        self.assertFalse(output_dir.exists())

    def test_delete_missing_raises(self):
        with self.assertRaises(ValueError):
            self.mgr.delete("nonexistent")

    def test_rename(self):
        self.mgr.create("old", "/tmp/code")
        p = self.mgr.rename("old", "new")
        self.assertEqual(p.name, "new")
        self.assertIsNone(self.mgr.load("old"))
        self.assertIsNotNone(self.mgr.load("new"))

    def test_rename_to_existing_raises(self):
        self.mgr.create("a", "/tmp/a")
        self.mgr.create("b", "/tmp/b")
        with self.assertRaises(ValueError):
            self.mgr.rename("a", "b")

    def test_rename_validates_new_name(self):
        self.mgr.create("a", "/tmp/a")
        with self.assertRaises(ValueError):
            self.mgr.rename("a", "none")

    def test_delete_clears_active_symlink(self):
        self.mgr.create("myapp", "/tmp/code")
        active = self.mgr.projects_dir / ".active"
        active.symlink_to("myapp.json")
        self.mgr.delete("myapp")
        self.assertFalse(active.is_symlink())

    def test_delete_preserves_other_active_symlink(self):
        self.mgr.create("myapp", "/tmp/code")
        self.mgr.create("other", "/tmp/other")
        active = self.mgr.projects_dir / ".active"
        active.symlink_to("other.json")
        self.mgr.delete("myapp")
        self.assertTrue(active.is_symlink())

    def test_rename_updates_active_symlink(self):
        self.mgr.create("old", "/tmp/code")
        active = self.mgr.projects_dir / ".active"
        active.symlink_to("old.json")
        self.mgr.rename("old", "new")
        self.assertEqual(os.readlink(active), "new.json")

    def test_set_active_updates_env_file(self):
        with TemporaryDirectory() as env_dir:
            env_file = Path(env_dir) / "claude_env"
            env_file.write_text('export PATH="$PATH:/something"\n')
            with patch.dict(os.environ, {"CLAUDE_ENV_FILE": str(env_file)}):
                self.mgr.create("myapp", "/tmp/code")
                self.mgr.set_active("myapp")
                content = env_file.read_text()
                self.assertIn("RAPTOR_PROJECT_DIR", content)
                self.assertIn("RAPTOR_PROJECT_NAME", content)
                self.assertIn("RAPTOR_PROJECT_TARGET", content)
                # PATH line should be preserved
                self.assertIn("/something", content)

    def test_set_active_none_clears_env_file(self):
        with TemporaryDirectory() as env_dir:
            env_file = Path(env_dir) / "claude_env"
            env_file.write_text(
                'export PATH="$PATH:/something"\n'
                'export RAPTOR_PROJECT_DIR="/old/path"\n'
                'export RAPTOR_PROJECT_NAME="old"\n'
            )
            with patch.dict(os.environ, {"CLAUDE_ENV_FILE": str(env_file)}):
                self.mgr.set_active(None)
                content = env_file.read_text()
                self.assertNotIn("RAPTOR_PROJECT_DIR", content)
                self.assertNotIn("RAPTOR_PROJECT_NAME", content)
                # PATH preserved
                self.assertIn("/something", content)

    def test_update_notes(self):
        self.mgr.create("myapp", "/tmp/code")
        p = self.mgr.update_notes("myapp", "new notes")
        self.assertEqual(p.notes, "new notes")
        # Verify persisted
        p2 = self.mgr.load("myapp")
        self.assertEqual(p2.notes, "new notes")

    def test_update_description(self):
        self.mgr.create("myapp", "/tmp/code")
        p = self.mgr.update_description("myapp", "new desc")
        self.assertEqual(p.description, "new desc")

    def test_find_project_for_target(self):
        self.mgr.create("myapp", "/tmp/code")
        found = self.mgr.find_project_for_target("/tmp/code")
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "myapp")

    def test_find_project_for_target_not_found(self):
        self.mgr.create("myapp", "/tmp/code")
        self.assertIsNone(self.mgr.find_project_for_target("/tmp/other"))

    def test_remove_run(self):
        p = self.mgr.create("myapp", "/tmp/code")
        run_dir = Path(p.output_dir) / "scan-20260406"
        run_dir.mkdir()
        (run_dir / "findings.json").write_text("{}")

        to_dir = Path(self.tmpdir.name) / "moved"
        self.mgr.remove_run("myapp", "scan-20260406", to_path=str(to_dir))
        self.assertFalse(run_dir.exists())
        self.assertTrue((to_dir / "scan-20260406" / "findings.json").exists())

    def test_remove_run_requires_to_path(self):
        self.mgr.create("myapp", "/tmp/code")
        with self.assertRaises(ValueError):
            self.mgr.remove_run("myapp", "scan-20260406")


class TestOutputDirResolution(unittest.TestCase):

    def test_raptor_project_dir_env(self):
        """RAPTOR_PROJECT_DIR env var should be readable."""
        os.environ["RAPTOR_PROJECT_DIR"] = "/tmp/test_project"
        try:
            self.assertEqual(os.environ.get("RAPTOR_PROJECT_DIR"), "/tmp/test_project")
        finally:
            del os.environ["RAPTOR_PROJECT_DIR"]


if __name__ == "__main__":
    unittest.main()
