"""Basic smoke tests for the project CLI."""

import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.cli import _get_active_project, main


class TestCLI(unittest.TestCase):

    def test_help(self):
        """main() with no args prints help without crashing."""
        with patch("sys.argv", ["raptor-project"]):
            # Should not raise
            main()

    def test_create(self):
        """Create subcommand creates a project file."""
        with TemporaryDirectory() as d:
            projects_dir = Path(d) / "projects"
            output_dir = Path(d) / "output"
            with patch("core.project.cli.ProjectManager") as MockMgr:
                instance = MockMgr.return_value
                instance.create.return_value = type("P", (), {
                    "name": "test", "output_dir": str(output_dir)
                })()
                with patch("sys.argv", ["raptor-project", "create", "test",
                                        "--target", "/tmp/code"]):
                    main()
                instance.create.assert_called_once()

    def test_list_empty(self):
        """List subcommand with no projects doesn't crash."""
        with patch("core.project.cli.ProjectManager") as MockMgr:
            instance = MockMgr.return_value
            instance.list_projects.return_value = []
            with patch("sys.argv", ["raptor-project", "list"]):
                main()
            instance.list_projects.assert_called_once()


class TestGetActiveProject(unittest.TestCase):
    """Tests for _get_active_project symlink resolution."""

    def test_symlink_resolves(self):
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            (projects_dir / "myapp.json").write_text('{"name":"myapp"}')
            active = projects_dir / ".active"
            active.symlink_to("myapp.json")

            with patch("core.project.project.PROJECTS_DIR", projects_dir):
                with patch.dict(os.environ, {}, clear=True):
                    result = _get_active_project()
            self.assertEqual(result, "myapp")

    def test_dangling_symlink_cleaned(self):
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            active = projects_dir / ".active"
            active.symlink_to("gone.json")

            with patch("core.project.project.PROJECTS_DIR", projects_dir):
                with patch.dict(os.environ, {}, clear=True):
                    result = _get_active_project()
            self.assertIsNone(result)
            self.assertFalse(active.exists() or active.is_symlink())

    def test_no_symlink_returns_none(self):
        with TemporaryDirectory() as d:
            with patch("core.project.project.PROJECTS_DIR", Path(d)):
                with patch.dict(os.environ, {}, clear=True):
                    result = _get_active_project()
            self.assertIsNone(result)

    def test_symlink_takes_priority_over_env(self):
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            (projects_dir / "myapp.json").write_text('{"name":"myapp"}')
            (projects_dir / ".active").symlink_to("myapp.json")

            with patch("core.project.project.PROJECTS_DIR", projects_dir):
                with patch.dict(os.environ, {"RAPTOR_PROJECT_NAME": "oldproject"}):
                    result = _get_active_project()
            # Symlink wins over env var
            self.assertEqual(result, "myapp")

    def test_env_var_used_when_no_symlink(self):
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            # No .active symlink
            with patch("core.project.project.PROJECTS_DIR", projects_dir):
                with patch.dict(os.environ, {"RAPTOR_PROJECT_NAME": "fromenv"}):
                    result = _get_active_project()
            self.assertEqual(result, "fromenv")


if __name__ == "__main__":
    unittest.main()
