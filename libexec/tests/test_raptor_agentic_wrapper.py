"""Tests for the libexec/raptor-agentic bash wrapper."""

import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


REPO_ROOT = Path(__file__).resolve().parents[2]  # libexec/tests -> repo root
WRAPPER = REPO_ROOT / "libexec" / "raptor-agentic"


class RaptorAgenticWrapperTests(unittest.TestCase):

    def test_wrapper_exists_and_is_executable(self):
        self.assertTrue(WRAPPER.exists(), msg=f"missing: {WRAPPER}")
        self.assertTrue(os.access(WRAPPER, os.X_OK),
                        msg=f"not executable: {WRAPPER}")

    def test_wrapper_passes_through_help_to_argparse(self):
        # --help must be handled by raptor_agentic.py argparse, not by the
        # wrapper. We assert the resulting output mentions agentic-specific
        # flags including the new --understand and --validate.
        proc = subprocess.run(
            [str(WRAPPER), "--help"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(proc.returncode, 0,
                         msg=f"wrapper --help failed: {proc.stderr}")
        self.assertIn("--understand", proc.stdout)
        self.assertIn("--validate", proc.stdout)
        self.assertIn("--repo", proc.stdout)

    def test_wrapper_propagates_unknown_arg_failure(self):
        # An unknown flag should bubble up as a non-zero exit from argparse,
        # not be silently swallowed by the wrapper.
        proc = subprocess.run(
            [str(WRAPPER), "--definitely-not-a-flag"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(proc.returncode, 0)
        # argparse writes errors to stderr.
        self.assertTrue(
            "unrecognized" in proc.stderr.lower()
            or "definitely-not-a-flag" in proc.stderr.lower(),
            msg=f"expected argparse error in stderr, got: {proc.stderr[:200]}",
        )

    def test_wrapper_fails_loudly_when_raptor_dir_invalid(self):
        # If the wrapper is somehow installed where ../raptor.py doesn't
        # exist (broken install, weird mount, manual file copy without the
        # rest of the repo), we must fail with a clear error pointing at
        # the resolved path — not a confusing python3 import error.
        with TemporaryDirectory() as tmp:
            broken = Path(tmp) / "fake-libexec" / "raptor-agentic"
            broken.parent.mkdir()
            # Copy the wrapper but NOT raptor.py — the parent dir is empty.
            broken.write_text(WRAPPER.read_text())
            broken.chmod(0o755)
            proc = subprocess.run(
                [str(broken), "--help"],
                capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("cannot find raptor.py", proc.stderr,
                          msg=f"expected explanatory error, got: {proc.stderr[:200]}")

    def test_wrapper_works_via_symlink(self):
        # The wrapper walks $0 symlinks so RAPTOR_DIR resolves correctly even
        # when invoked via a symlink in ~/bin or similar.
        with TemporaryDirectory() as tmp:
            link = Path(tmp) / "raptor-agentic"
            link.symlink_to(WRAPPER)
            proc = subprocess.run(
                [str(link), "--help"],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(proc.returncode, 0,
                             msg=f"symlinked wrapper failed: {proc.stderr}")
            self.assertIn("--understand", proc.stdout)


if __name__ == "__main__":
    unittest.main()
