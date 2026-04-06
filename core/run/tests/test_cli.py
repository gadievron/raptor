"""Tests for the run lifecycle CLI stubs (python3 -m core.run)."""

import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.json import load_json
from core.run.metadata import RUN_METADATA_FILE


def _run_stub(*args, env_extra=None):
    """Run python3 -m core.run with given args."""
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        [sys.executable, "-m", "core.run"] + list(args),
        capture_output=True, text=True, env=env,
    )
    return result


class TestRunCLI(unittest.TestCase):

    def test_start_creates_dir_and_metadata(self):
        with TemporaryDirectory() as d:
            result = _run_stub("start", "scan", env_extra={"RAPTOR_PROJECT_DIR": d})
            self.assertEqual(result.returncode, 0)
            out_dir = Path(result.stdout.strip())
            self.assertTrue(out_dir.exists())
            self.assertTrue(out_dir.name.startswith("scan-"))
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["command"], "scan")
            self.assertEqual(meta["status"], "running")

    def test_complete_updates_status(self):
        with TemporaryDirectory() as d:
            # Start
            result = _run_stub("start", "validate", env_extra={"RAPTOR_PROJECT_DIR": d})
            out_dir = Path(result.stdout.strip())
            # Complete
            result = _run_stub("complete", str(out_dir))
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")

    def test_fail_updates_status_with_error(self):
        with TemporaryDirectory() as d:
            result = _run_stub("start", "scan", env_extra={"RAPTOR_PROJECT_DIR": d})
            out_dir = Path(result.stdout.strip())
            result = _run_stub("fail", str(out_dir), "semgrep crashed")
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["extra"]["error"], "semgrep crashed")

    def test_cancel_updates_status(self):
        with TemporaryDirectory() as d:
            result = _run_stub("start", "scan", env_extra={"RAPTOR_PROJECT_DIR": d})
            out_dir = Path(result.stdout.strip())
            result = _run_stub("cancel", str(out_dir))
            self.assertEqual(result.returncode, 0)
            meta = load_json(out_dir / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "cancelled")

    def test_start_no_command_fails(self):
        result = _run_stub("start")
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_action_fails(self):
        result = _run_stub("bogus")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
