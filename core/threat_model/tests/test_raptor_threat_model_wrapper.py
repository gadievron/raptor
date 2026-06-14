"""Tests for the libexec/raptor-threat-model bash wrapper."""

import os
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
WRAPPER = REPO_ROOT / "libexec" / "raptor-threat-model"


def _env():
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    return env


class RaptorThreatModelWrapperTests(unittest.TestCase):

    def test_wrapper_exists_and_is_executable(self):
        self.assertTrue(WRAPPER.exists(), msg=f"missing: {WRAPPER}")
        self.assertTrue(os.access(WRAPPER, os.X_OK),
                        msg=f"not executable: {WRAPPER}")

    def test_help_prints_usage(self):
        proc = subprocess.run(
            [str(WRAPPER), "--help"],
            capture_output=True, text=True, timeout=15, env=_env(),
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("Usage: raptor-threat-model", proc.stdout)
        self.assertIn("build", proc.stdout)
        self.assertIn("refresh", proc.stdout)

    def test_unknown_command_fails_cleanly(self):
        proc = subprocess.run(
            [str(WRAPPER), "nonsense"],
            capture_output=True, text=True, timeout=15, env=_env(),
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unknown command", proc.stderr.lower())

    def test_show_routes_to_project_threat_model(self):
        proc = subprocess.run(
            [str(WRAPPER), "show"],
            capture_output=True, text=True, timeout=15, env=_env(),
        )
        combined = (proc.stdout + proc.stderr).lower()
        # The wrapper either prints "threat model" prose or routes
        # to ``raptor project threat-model …`` (hyphenated CLI form).
        # Accept either — both prove the show routing worked.
        self.assertTrue(
            "threat model" in combined or "threat-model" in combined,
            f"neither 'threat model' nor 'threat-model' in: {combined!r}",
        )

    def test_build_help_routes_to_agentic_help(self):
        proc = subprocess.run(
            [str(WRAPPER), "build", "--help"],
            capture_output=True, text=True, timeout=15, env=_env(),
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("--threat-model-only", proc.stdout)
        self.assertIn("--threat-model-use-stale", proc.stdout)


if __name__ == "__main__":
    unittest.main()
