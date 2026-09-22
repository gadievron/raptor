"""The launcher's session-scratch advisory must never abort the launch.

Why this test exists
--------------------
``bin/raptor`` runs under ``set -euo pipefail`` and, after sweeping
stale ``session-*`` dirs, measures the scratch base with
``du -sk | cut`` purely to print a >5G advisory. ``du`` exits nonzero
whenever an entry vanishes mid-walk (live sibling sessions churn
scratch in the shared base) or is unreadable — while still printing
the total it summed. With the measurement's stderr nulled, that
status propagated through ``pipefail`` into ``set -e`` and killed the
launcher: a silent, race-dependent exit 1 before Claude Code ever
started. The advisory lane must tolerate a failing ``du``.

``--help`` is the earliest exit after the TMPDIR block, so the case
runs the real launcher without launching Claude Code.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO / "bin" / "raptor"


def _run_help(extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = {
        "HOME": os.environ.get("HOME", "/tmp"),
        "PATH": "/usr/bin:/bin",
    }
    env.update(extra_env)
    return subprocess.run(
        ["bash", str(_LAUNCHER), "--help"],
        capture_output=True, text=True, timeout=60, env=env,
    )


class TestScratchAdvisorySurvivesDuFailure(unittest.TestCase):
    def test_unreadable_scratch_entry_does_not_abort_launch(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root ignores directory mode bits; du cannot fail")
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / f"raptor-{os.getuid()}"
            base.mkdir(mode=0o700)
            unreadable = base / "scratch-junk"
            unreadable.mkdir()
            unreadable.chmod(0)
            try:
                proc = _run_help({"RAPTOR_WORK_DIR": d})
            finally:
                unreadable.chmod(0o700)
        self.assertEqual(
            proc.returncode, 0,
            f"launcher died on a failing du (advisory lane):\n{proc.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
