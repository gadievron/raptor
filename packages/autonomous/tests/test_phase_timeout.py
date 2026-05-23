"""Tests for the --phase-timeout CLI flag + run_command_streaming plumbing.

Power-user / kernel-scale targets (FreeBSD, Chromium, etc.) need the
analysis subprocess to run for hours, not minutes. Pre-fix three call
sites hardcoded ``timeout=1800`` (30 min) — non-overridable, would TLE
kernel-scale runs every time. The fix surfaces a single
``--phase-timeout SECONDS`` knob (0 = unbounded) plumbed to all three.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

# parents[3] climbs:
#   [0] packages/autonomous/tests/
#   [1] packages/autonomous/
#   [2] packages/
#   [3] <repo root>
REPO_ROOT = Path(__file__).resolve().parents[3]
RAPTOR_AGENTIC = REPO_ROOT / "raptor_agentic.py"


class PhaseTimeoutArgparseTests(unittest.TestCase):
    """The CLI flag itself: present in --help, parses, defaults to 1800."""

    def _run_help(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(RAPTOR_AGENTIC), "--help"],
            capture_output=True, text=True, timeout=15,
            env={**os.environ, "RAPTOR_DIR": str(REPO_ROOT)},
        )

    def test_flag_visible_in_help(self):
        proc = self._run_help()
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--phase-timeout", proc.stdout)

    def test_help_mentions_zero_disables(self):
        """The help text must call out the ``0 = unbounded`` sentinel —
        otherwise power users won't know they have an escape hatch."""
        proc = self._run_help()
        self.assertEqual(proc.returncode, 0)
        self.assertIn("0", proc.stdout)
        # And mention kernel-scale or unbounded so the use case is clear
        self.assertTrue(
            "kernel-scale" in proc.stdout or "unbounded" in proc.stdout,
            msg="help text should mention unbounded/kernel-scale use case",
        )


class RaptorCodeqlPhaseTimeoutTests(unittest.TestCase):
    """`/codeql --phase-timeout` parses + mutates RaptorConfig.CODEQL_TIMEOUT.

    Different plumbing pattern from /agentic: /codeql's subprocess calls
    live inside ``packages/codeql/`` package code which reads
    ``RaptorConfig.CODEQL_TIMEOUT``. The CLI flag mutates that constant
    at startup so package-internal calls pick up the override without
    per-call argument plumbing.
    """

    RAPTOR_CODEQL = REPO_ROOT / "raptor_codeql.py"

    def _run_help(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(self.RAPTOR_CODEQL), "--help"],
            capture_output=True, text=True, timeout=15,
            env={**os.environ, "RAPTOR_DIR": str(REPO_ROOT)},
        )

    def test_flag_visible_in_help(self):
        proc = self._run_help()
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("--phase-timeout", proc.stdout)

    def test_help_mentions_kernel_scale_or_unbounded(self):
        """Same operator-context hint pattern as /agentic."""
        proc = self._run_help()
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(
            "kernel-scale" in proc.stdout or "unbounded" in proc.stdout,
            msg="help should explain the 0/unbounded sentinel use case",
        )

    def test_help_text_mentions_RaptorConfig_default(self):
        """The default should reference the RaptorConfig constant so
        operators know where to find/raise it framework-wide."""
        proc = self._run_help()
        self.assertEqual(proc.returncode, 0)
        self.assertIn("CODEQL_TIMEOUT", proc.stdout)


class RunCommandStreamingTimeoutTests(unittest.TestCase):
    """run_command_streaming forwards its timeout arg to process.wait."""

    def _import_helper(self):
        """Import run_command_streaming with sys.path safe."""
        path_added = False
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
            path_added = True
        try:
            from raptor_agentic import run_command_streaming
            return run_command_streaming
        finally:
            if path_added:
                sys.path.remove(str(REPO_ROOT))

    def test_default_timeout_is_1800(self):
        """Backward-compat: callers that don't pass timeout get 30 min."""
        run_command_streaming = self._import_helper()
        # Inspect the function's default param value.
        import inspect
        sig = inspect.signature(run_command_streaming)
        assert sig.parameters["timeout"].default == 1800

    def _make_fake_popen(self, captured: list):
        """Build a FakePopen class that captures wait() timeouts +
        provides stdout/stderr pipe-likes so the streaming threads
        don't crash before wait() is reached (pytest captures stderr
        differently from a bare REPL; thread crash before wait()
        can leave the captured list empty)."""
        import io

        class FakePopen:
            returncode = 0

            def __init__(self, *a, **kw):
                # Provide empty pipe-likes that the stream_output thread
                # can readline() + close() without raising. EOF-on-first-
                # read terminates the loop cleanly.
                self.stdout = io.StringIO("")
                self.stderr = io.StringIO("")

            def wait(self, timeout=None):
                captured.append(timeout)
                return 0

            def kill(self):
                pass

            def poll(self):
                return 0

        return FakePopen

    def test_zero_timeout_becomes_none_to_subprocess(self):
        """``timeout=0`` is the unbounded sentinel — must be passed as
        ``None`` to ``subprocess.Popen.wait`` (subprocess interprets
        ``None`` as 'no timeout', ``0`` as 'expire immediately')."""
        run_command_streaming = self._import_helper()
        captured: list = []

        with mock.patch("subprocess.Popen", self._make_fake_popen(captured)):
            run_command_streaming(["echo", "x"], "test", timeout=0)

        # `0 or None` evaluates to None — the unbounded-wait sentinel.
        assert captured == [None], (
            f"expected wait(timeout=None) for the unbounded case; got: {captured}"
        )

    def test_positive_timeout_passed_through(self):
        """Non-zero timeouts pass straight through to process.wait."""
        run_command_streaming = self._import_helper()
        captured: list = []

        with mock.patch("subprocess.Popen", self._make_fake_popen(captured)):
            run_command_streaming(["echo", "x"], "test", timeout=7200)

        assert captured == [7200], (
            f"expected wait(timeout=7200); got: {captured}"
        )


if __name__ == "__main__":
    unittest.main()
