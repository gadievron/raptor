"""Tests for output directory resolution."""

import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.run.output import get_output_dir, TargetMismatchError

# Mock that disables project resolution — for testing standalone (no project) mode.
_NO_SYMLINK = patch("core.run.output._resolve_active_project", return_value=None)


class TestGetOutputDir(unittest.TestCase):

    @_NO_SYMLINK
    def test_explicit_out_takes_priority(self, _mock):
        with TemporaryDirectory() as d:
            explicit = os.path.join(d, "my-output")
            result = get_output_dir("scan", target_name="repo", explicit_out=explicit)
            self.assertEqual(result, Path(explicit).resolve())

    def test_project_dir_produces_hyphen_subdir(self):
        with TemporaryDirectory() as d:
            with patch("core.run.output._resolve_active_project",
                       return_value=(d, "test", "")):
                result = get_output_dir("scan")
                self.assertEqual(result.parent, Path(d))
                self.assertTrue(result.name.startswith("scan-"))
                self.assertNotIn("_", result.name.split("-", 1)[1][:8])

    @_NO_SYMLINK
    def test_default_produces_underscore_dirname(self, _mock):
        result = get_output_dir("scan", target_name="myrepo")
        self.assertIn("scan_myrepo_", result.name)

    @_NO_SYMLINK
    def test_empty_target_omits_target(self, _mock):
        result = get_output_dir("scan", target_name="")
        self.assertTrue(result.name.startswith("scan_"))
        parts = result.name.split("_")
        self.assertEqual(len(parts), 3)


def _mock_project(d, name="myapp", target="/tmp/vulns"):
    """Create a mock for _resolve_active_project that returns test values."""
    return patch("core.run.output._resolve_active_project",
                 return_value=(d, name, target))


class TestTargetMismatch(unittest.TestCase):

    def test_matching_target_ok(self):
        with TemporaryDirectory() as d:
            with _mock_project(d):
                get_output_dir("scan", target_path="/tmp/vulns")

    def test_subdirectory_target_ok(self):
        with TemporaryDirectory() as d:
            with _mock_project(d):
                get_output_dir("scan", target_path="/tmp/vulns/src/parser")

    def test_different_target_raises(self):
        with TemporaryDirectory() as d:
            with _mock_project(d):
                with self.assertRaises(TargetMismatchError) as ctx:
                    get_output_dir("scan", target_path="/tmp/other")
                self.assertIn("outside project", str(ctx.exception))
                self.assertIn("/project create", str(ctx.exception))
                self.assertIn("/project use none", str(ctx.exception))

    def test_no_project_target_skips_check(self):
        with TemporaryDirectory() as d:
            with _mock_project(d, target=""):
                get_output_dir("scan", target_path="/tmp/anything")

    def test_caller_dir_mismatch_raises(self):
        """RAPTOR_CALLER_DIR is used for mismatch check when no explicit target."""
        with TemporaryDirectory() as d:
            env = {"RAPTOR_CALLER_DIR": "/tmp/other"}
            with patch.dict(os.environ, env):
                with _mock_project(d):
                    with self.assertRaises(TargetMismatchError):
                        get_output_dir("scan")

    def test_caller_dir_matches(self):
        """RAPTOR_CALLER_DIR matching project target is fine."""
        with TemporaryDirectory() as d:
            env = {"RAPTOR_CALLER_DIR": "/tmp/vulns"}
            with patch.dict(os.environ, env):
                with _mock_project(d):
                    get_output_dir("scan")

    def test_explicit_out_skips_check(self):
        with TemporaryDirectory() as d:
            with _mock_project(d):
                result = get_output_dir("scan", explicit_out="/tmp/manual",
                                        target_path="/tmp/other")
                self.assertEqual(result, Path("/tmp/manual").resolve())


if __name__ == "__main__":
    unittest.main()
