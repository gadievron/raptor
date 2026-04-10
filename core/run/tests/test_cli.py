"""Tests for the run lifecycle CLI stubs (python3 -m core.run)."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.json import load_json
from core.run.metadata import RUN_METADATA_FILE


def _run_stub(*args, env_extra=None, tmp_home=None):
    """Run python3 -m core.run with given args.

    Uses a temporary HOME to isolate from the real .active symlink.
    """
    env = os.environ.copy()
    if tmp_home:
        env["HOME"] = tmp_home
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        [sys.executable, "-m", "core.run"] + list(args),
        capture_output=True, text=True, env=env,
    )
    return result


def _setup_project_symlink(home_dir, project_dir):
    """Create a .active symlink in a temp home pointing to a project."""
    projects_dir = Path(home_dir) / ".raptor" / "projects"
    projects_dir.mkdir(parents=True, exist_ok=True)
    # Write project JSON
    project_json = projects_dir / "_test.json"
    project_json.write_text(json.dumps({
        "name": "_test",
        "target": "/tmp",
        "output_dir": str(project_dir),
    }))
    # Create .active symlink
    active = projects_dir / ".active"
    if active.is_symlink() or active.exists():
        active.unlink()
    active.symlink_to("_test.json")


class TestRunCLI(unittest.TestCase):

    def test_start_creates_dir_and_metadata(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run_stub("start", "scan", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            out_dir = Path(result.stdout.strip())
            self.assertTrue(out_dir.exists())
            self.assertTrue(out_dir.name.startswith("scan-"))
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["command"], "scan")
            self.assertEqual(meta["status"], "running")

    def test_complete_updates_status(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run_stub("start", "validate", tmp_home=home)
            out_dir = Path(result.stdout.strip())
            result = _run_stub("complete", str(out_dir))
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")

    def test_fail_updates_status_with_error(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run_stub("start", "scan", tmp_home=home)
            out_dir = Path(result.stdout.strip())
            result = _run_stub("fail", str(out_dir), "semgrep crashed")
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["extra"]["error"], "semgrep crashed")

    def test_cancel_updates_status(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as home:
            _setup_project_symlink(home, d)
            result = _run_stub("start", "scan", tmp_home=home)
            out_dir = Path(result.stdout.strip())
            result = _run_stub("cancel", str(out_dir))
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "cancelled")

    def test_standalone_mode(self):
        """Without a project symlink, creates underscore-style dir in out/."""
        with TemporaryDirectory() as home:
            result = _run_stub("start", "scan", tmp_home=home)
            self.assertEqual(result.returncode, 0, result.stderr)
            out_dir = Path(result.stdout.strip())
            self.assertTrue(out_dir.name.startswith("scan_"))

    def test_start_no_command_fails(self):
        result = _run_stub("start")
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_action_fails(self):
        result = _run_stub("bogus")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
