"""Tests for libexec/raptor-run-lifecycle."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.json import load_json
from core.run.metadata import RUN_METADATA_FILE

REPO_ROOT = Path(__file__).resolve().parents[3]  # core/run/tests -> repo root
LIFECYCLE = str(REPO_ROOT / "libexec" / "raptor-run-lifecycle")


def _run(*args, tmp_home=None):
    """Run libexec/raptor-run-lifecycle with given args."""
    env = os.environ.copy()
    if tmp_home:
        env["HOME"] = tmp_home
    result = subprocess.run(
        [sys.executable, LIFECYCLE] + list(args),
        capture_output=True, text=True, env=env,
    )
    return result


def _setup_project_symlink(home_dir, project_dir):
    """Create a .active symlink in a temp home pointing to a project."""
    projects_dir = Path(home_dir) / ".raptor" / "projects"
    projects_dir.mkdir(parents=True, exist_ok=True)
    project_json = projects_dir / "_test.json"
    project_json.write_text(json.dumps({
        "name": "_test",
        "target": "/tmp",
        "output_dir": str(project_dir),
    }))
    active = projects_dir / ".active"
    if active.is_symlink() or active.exists():
        active.unlink()
    active.symlink_to("_test.json")


class TestRunLifecycle(unittest.TestCase):

    def test_start_creates_dir_and_metadata(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run("start", "scan", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Last line is OUTPUT_DIR=<path>
            out_dir = Path(result.stdout.strip().split("=", 1)[1])
            self.assertTrue(out_dir.exists())
            self.assertTrue(out_dir.name.startswith("scan-"))
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["command"], "scan")
            self.assertEqual(meta["status"], "running")

    def test_complete_updates_status(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run("start", "validate", tmp_home=home)
            out_dir = Path(result.stdout.strip().split("=", 1)[1])
            result = _run("complete", str(out_dir))
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")

    def test_fail_updates_status_with_error(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run("start", "scan", tmp_home=home)
            out_dir = Path(result.stdout.strip().split("=", 1)[1])
            result = _run("fail", str(out_dir), "semgrep crashed")
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["extra"]["error"], "semgrep crashed")

    def test_cancel_updates_status(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run("start", "scan", tmp_home=home)
            out_dir = Path(result.stdout.strip().split("=", 1)[1])
            result = _run("cancel", str(out_dir))
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "cancelled")

    def test_standalone_mode(self):
        """Without a project symlink, creates underscore-style dir in out/."""
        with TemporaryDirectory() as home:
            result = _run("start", "scan", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            out_dir = Path(result.stdout.strip().split("=", 1)[1])
            self.assertTrue(out_dir.name.startswith("scan_"))

    def test_start_no_command_fails(self):
        result = _run("start")
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_action_fails(self):
        result = _run("bogus")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
