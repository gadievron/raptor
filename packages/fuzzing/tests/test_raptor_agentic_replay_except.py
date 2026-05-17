"""Test for the narrow `except` clause in raptor_agentic._replay_fuzz_crashes.

Per PR #488 review (grokjc): the replay loop must catch only
(OSError, subprocess.SubprocessError, ValueError) — anything else
must propagate so operators see real bugs instead of them silently
turning into "reproduced=False" replay entries.

Drives _replay_fuzz_crashes against a temp dir with a stubbed
sandbox.run that raises various exception types, asserting which
get swallowed vs which propagate.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(os.environ["RAPTOR_DIR"])
sys.path.insert(0, str(REPO_ROOT))


class TestReplayExceptNarrowing(unittest.TestCase):
    """The except clause in _replay_fuzz_crashes only catches the
    documented narrow tuple. Other exceptions propagate."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="replay-except-test-")
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.tmp, ignore_errors=True,
        ))
        self.binary = Path(self.tmp) / "target"
        self.binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
        self.binary.chmod(0o755)
        # _candidate_replay_binaries looks for sibling `<stem>_asan`
        # / `<stem>_debug` and only includes them if they exist and
        # are executable. Create the asan sibling so the except path
        # inside _replay_fuzz_crashes actually executes.
        asan_sibling = Path(self.tmp) / "target_asan"
        asan_sibling.write_bytes(b"\x7fELF" + b"\x00" * 60)
        asan_sibling.chmod(0o755)
        self.crash_file = Path(self.tmp) / "crash-input"
        self.crash_file.write_bytes(b"\x41" * 16)
        self.out_dir = Path(self.tmp) / "out"

    def _run_with_sandbox_raising(self, exc):
        """Invoke _replay_fuzz_crashes with sandbox.run patched to
        raise the given exception."""
        from raptor_agentic import _replay_fuzz_crashes
        # _replay_fuzz_crashes does `from core.sandbox import run as
        # _sandbox_run` lazily inside the function, so patch the
        # source-module attribute (core.sandbox.run) which is what
        # the lazy import will resolve to.
        with patch("core.sandbox.run", side_effect=exc):
            return _replay_fuzz_crashes(
                binary_path=self.binary,
                crash_files=[self.crash_file],
                out_dir=self.out_dir,
            )

    # === Caught (narrow tuple — should produce a "reproduced=False" entry) ===

    def test_oserror_is_caught(self):
        result = self._run_with_sandbox_raising(
            OSError("simulated FS failure"),
        )
        entries = result.get(str(self.crash_file), [])
        self.assertTrue(any(e.get("error") for e in entries),
                        f"OSError should be caught + logged: {entries}")

    def test_subprocess_called_process_error_is_caught(self):
        exc = subprocess.CalledProcessError(returncode=1, cmd="x")
        result = self._run_with_sandbox_raising(exc)
        entries = result.get(str(self.crash_file), [])
        self.assertTrue(any(e.get("error") for e in entries),
                        f"CalledProcessError should be caught: {entries}")

    def test_value_error_is_caught(self):
        result = self._run_with_sandbox_raising(
            ValueError("simulated bad arg"),
        )
        entries = result.get(str(self.crash_file), [])
        self.assertTrue(any(e.get("error") for e in entries),
                        f"ValueError should be caught: {entries}")

    # === NOT caught (must propagate — real bugs, not replay failures) ===

    def test_runtime_error_propagates(self):
        """RuntimeError is the canonical "something unexpected went
        wrong in our own code" exception. Pre-narrowing it was
        swallowed and the operator never saw the bug."""
        with self.assertRaises(RuntimeError):
            self._run_with_sandbox_raising(
                RuntimeError("real bug in sandbox setup"),
            )

    def test_attribute_error_propagates(self):
        """AttributeError typically means "we called a method that
        doesn't exist" — a real RAPTOR bug. Must NOT be swallowed."""
        with self.assertRaises(AttributeError):
            self._run_with_sandbox_raising(
                AttributeError("None has no .returncode"),
            )

    def test_keyboard_interrupt_propagates(self):
        """Ctrl-C must always propagate — operator interrupts mean
        STOP, not 'record this as a failed replay and continue'."""
        with self.assertRaises(KeyboardInterrupt):
            self._run_with_sandbox_raising(KeyboardInterrupt())


if __name__ == "__main__":
    unittest.main()
