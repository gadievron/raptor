"""The launcher's session-scratch maintenance must never abort the launch.

Why this test exists
--------------------
``bin/raptor`` runs under ``set -euo pipefail``, and two lanes of the
per-session TMPDIR block execute fallible commands at statement level:

* the advisory scratch-size measurement (``du -sk | cut``): ``du``
  exits nonzero whenever an entry vanishes mid-walk (live sibling
  sessions churn scratch in the shared base) or is unreadable — while
  still printing the total it summed. With the measurement's stderr
  nulled, that status propagated through ``pipefail`` into ``set -e``
  and killed the launcher: a silent, race-dependent exit 1.
* the stale-session sweep's ``rm -rf``: undeletable leftovers inside
  a dead session's dir (a non-empty unreadable subdir; root-owned
  files from container/sandbox tool runs) made ``rm`` exit nonzero —
  and because the stale dir survives, every subsequent launch
  re-failed the same way until cleaned by hand.

Both lanes are maintenance, not preconditions: the launch must
survive their failure (with a bounded warning for the sweep lane).

``--help`` is the earliest exit after the TMPDIR block, so the cases
run the real launcher without launching Claude Code; asserting the
usage text pins that the launcher actually traversed the block.
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


def _dead_pid() -> int:
    """A pid that ``kill -0`` rejects (ESRCH), so the sweep treats a
    session dir named for it as stale. Values above the kernel's
    pid_max also raise ESRCH, which serves equally."""
    pid = 4194000
    while pid > 2:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return pid
        except PermissionError:
            pass  # alive under another uid — keep looking
        pid -= 1
    raise RuntimeError("no dead pid found")


class TestScratchMaintenanceSurvivesFailure(unittest.TestCase):
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
        self.assertIn("Usage:", proc.stdout)

    def test_undeletable_stale_session_dir_does_not_abort_launch(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root ignores directory mode bits; rm cannot fail")
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / f"raptor-{os.getuid()}"
            base.mkdir(mode=0o700)
            junk = base / f"session-{_dead_pid()}-1" / "junk"
            junk.mkdir(parents=True)
            (junk / "f").write_text("x")
            junk.chmod(0)
            try:
                proc = _run_help({"RAPTOR_WORK_DIR": d})
            finally:
                junk.chmod(0o700)
        self.assertEqual(
            proc.returncode, 0,
            f"launcher died on a failing stale-dir rm (sweep lane):\n{proc.stderr}",
        )
        self.assertIn("Usage:", proc.stdout)
        self.assertIn("could not fully remove stale session dir", proc.stderr)


if __name__ == "__main__":
    unittest.main()
