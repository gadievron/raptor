"""Tests for raptor_agentic._PipeDrainer.

Regression: the "parallel" Semgrep+CodeQL children were spawned with
stdout/stderr PIPEs but drained sequentially — the second child blocked
in write() once its output exceeded the OS pipe buffer (~64KB), pinning
it until the first child finished. _PipeDrainer reads each stream in a
background thread so both children make progress concurrently.
"""

from __future__ import annotations

import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from raptor_agentic import _PipeDrainer

# Writes well past the OS pipe buffer (~64KB) then exits: an undrained
# PIPE'd child running this stays blocked in write() forever.
_CHATTY = (
    "import sys\n"
    "sys.stdout.write('x' * (512 * 1024))\n"
    "sys.stderr.write('e' * (256 * 1024))\n"
)


def _spawn_chatty() -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", _CHATTY],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


class PipeDrainerTests(unittest.TestCase):

    def test_chatty_child_exits_while_parent_is_busy_elsewhere(self):
        """The child must not stay blocked on a full pipe while the
        parent waits on a sibling (the pre-fix failure mode)."""
        proc = _spawn_chatty()
        try:
            drainer = _PipeDrainer(proc)
            # Simulate the parent being busy draining the sibling.
            deadline = time.monotonic() + 20
            while proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertIsNotNone(
                proc.poll(),
                "child stayed blocked on a full pipe despite the drainer",
            )
            stdout, stderr = drainer.collect(timeout=10)
            self.assertEqual(len(stdout), 512 * 1024)
            self.assertEqual(len(stderr), 256 * 1024)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)

    def test_collect_raises_timeout_expired_like_communicate(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            drainer = _PipeDrainer(proc)
            with self.assertRaises(subprocess.TimeoutExpired):
                drainer.collect(timeout=0.2)
            # Post-kill collect drains what exists — the pattern the
            # scanner timeout handler relies on.
            proc.kill()
            stdout, stderr = drainer.collect(timeout=10)
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
