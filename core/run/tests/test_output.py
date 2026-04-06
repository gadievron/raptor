"""Tests for output directory resolution."""

import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.run.output import get_output_dir, TargetMismatchError


class TestGetOutputDir(unittest.TestCase):

    def test_explicit_out_takes_priority(self):
        with TemporaryDirectory() as d:
            explicit = os.path.join(d, "my-output")
            result = get_output_dir("scan", target_name="repo", explicit_out=explicit)
            self.assertEqual(result, Path(explicit).resolve())

    def test_project_dir_produces_hyphen_subdir(self):
        with TemporaryDirectory() as d:
            with patch.dict(os.environ, {"RAPTOR_PROJECT_DIR": d}):
                result = get_output_dir("scan")
                self.assertEqual(result.parent, Path(d))
                # Project mode uses hyphens: command-timestamp
                self.assertTrue(result.name.startswith("scan-"))
                self.assertNotIn("_", result.name.split("-", 1)[1][:8])

    def test_default_produces_underscore_dirname(self):
        with patch.dict(os.environ, {}, clear=True):
            # Remove RAPTOR_PROJECT_DIR if set
            env = os.environ.copy()
            env.pop("RAPTOR_PROJECT_DIR", None)
            with patch.dict(os.environ, env, clear=True):
                result = get_output_dir("scan", target_name="myrepo")
                # Standalone mode uses underscores: command_target_timestamp
                self.assertIn("scan_myrepo_", result.name)

    def test_empty_target_omits_target(self):
        with patch.dict(os.environ, {}, clear=True):
            env = os.environ.copy()
            env.pop("RAPTOR_PROJECT_DIR", None)
            with patch.dict(os.environ, env, clear=True):
                result = get_output_dir("scan", target_name="")
                # Should be command_timestamp without target
                self.assertTrue(result.name.startswith("scan_"))
                parts = result.name.split("_")
                # No target part: scan_YYYYMMDD_HHMMSS (3 parts)
                self.assertEqual(len(parts), 3)


class TestTargetMismatch(unittest.TestCase):

    def test_matching_target_ok(self):
        with TemporaryDirectory() as d:
            env = {"RAPTOR_PROJECT_DIR": d, "RAPTOR_PROJECT_TARGET": "/tmp/vulns",
                   "RAPTOR_PROJECT_NAME": "myapp"}
            with patch.dict(os.environ, env):
                # Should not raise
                get_output_dir("scan", target_path="/tmp/vulns")

    def test_subdirectory_target_ok(self):
        with TemporaryDirectory() as d:
            env = {"RAPTOR_PROJECT_DIR": d, "RAPTOR_PROJECT_TARGET": "/tmp/vulns",
                   "RAPTOR_PROJECT_NAME": "myapp"}
            with patch.dict(os.environ, env):
                # Subdirectory of target — should not raise
                get_output_dir("scan", target_path="/tmp/vulns/src/parser")

    def test_different_target_raises(self):
        with TemporaryDirectory() as d:
            env = {"RAPTOR_PROJECT_DIR": d, "RAPTOR_PROJECT_TARGET": "/tmp/vulns",
                   "RAPTOR_PROJECT_NAME": "myapp"}
            with patch.dict(os.environ, env):
                with self.assertRaises(TargetMismatchError) as ctx:
                    get_output_dir("scan", target_path="/tmp/other")
                self.assertIn("outside project", str(ctx.exception))
                self.assertIn("raptor project create", str(ctx.exception))
                self.assertIn("raptor project use none", str(ctx.exception))

    def test_no_project_target_skips_check(self):
        with TemporaryDirectory() as d:
            env = {"RAPTOR_PROJECT_DIR": d}
            with patch.dict(os.environ, env):
                # No RAPTOR_PROJECT_TARGET — should not raise
                get_output_dir("scan", target_path="/tmp/anything")

    def test_no_target_no_caller_dir_skips_check(self):
        """Without target_path or RAPTOR_CALLER_DIR, mismatch check is skipped."""
        with TemporaryDirectory() as d:
            env = {"RAPTOR_PROJECT_DIR": d, "RAPTOR_PROJECT_TARGET": "/tmp/vulns",
                   "RAPTOR_PROJECT_NAME": "myapp"}
            with patch.dict(os.environ, env):
                # No target_path, no RAPTOR_CALLER_DIR — should not raise
                get_output_dir("scan")

    def test_caller_dir_mismatch_raises(self):
        """RAPTOR_CALLER_DIR is used for mismatch check when no explicit target."""
        with TemporaryDirectory() as d:
            env = {"RAPTOR_PROJECT_DIR": d, "RAPTOR_PROJECT_TARGET": "/tmp/vulns",
                   "RAPTOR_PROJECT_NAME": "myapp", "RAPTOR_CALLER_DIR": "/tmp/other"}
            with patch.dict(os.environ, env):
                with self.assertRaises(TargetMismatchError):
                    get_output_dir("scan")

    def test_caller_dir_matches(self):
        """RAPTOR_CALLER_DIR matching project target is fine."""
        with TemporaryDirectory() as d:
            env = {"RAPTOR_PROJECT_DIR": d, "RAPTOR_PROJECT_TARGET": "/tmp/vulns",
                   "RAPTOR_PROJECT_NAME": "myapp", "RAPTOR_CALLER_DIR": "/tmp/vulns"}
            with patch.dict(os.environ, env):
                get_output_dir("scan")

    def test_explicit_out_skips_check(self):
        with TemporaryDirectory() as d:
            env = {"RAPTOR_PROJECT_DIR": d, "RAPTOR_PROJECT_TARGET": "/tmp/vulns",
                   "RAPTOR_PROJECT_NAME": "myapp"}
            with patch.dict(os.environ, env):
                # explicit_out bypasses project entirely
                result = get_output_dir("scan", explicit_out="/tmp/manual",
                                        target_path="/tmp/other")
                self.assertEqual(result, Path("/tmp/manual").resolve())


if __name__ == "__main__":
    unittest.main()
