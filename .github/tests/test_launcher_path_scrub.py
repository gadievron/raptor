"""The launcher's PATH-scrub warnings must not echo the hostile bytes
they classified.

Why this test exists
--------------------
``bin/raptor``'s own threat model names PATH entries
attacker-influenceable (a hostile direnv/.envrc poisons PATH before
the launcher runs), and the scrub correctly DROPS empty/relative/
world-writable entries — but the warning lanes then wrote the flagged
entry verbatim to the operator's TTY at the exact launch moment. A
planted entry carrying ESC/CSI overwrote or forged the very hygiene
warning that reported it. The bash lanes are outside the AST
writer-gate's reach (manual-audit tier), so this behavioural pin is
the lane's oracle: both scrub passes must strip non-printables from
what they echo while still refusing the entry.

``--help`` is the earliest post-scrub exit, so each case runs the real
launcher without launching Claude Code.
"""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO / "bin" / "raptor"

_HOSTILE = "\x1b]0;pwned\x07"


def _run_help(path_value: str, extra_env: dict | None = None):
    env = {
        "HOME": os.environ.get("HOME", "/tmp"),
        "PATH": path_value,
    }
    if extra_env:
        env.update(extra_env)
    with tempfile.TemporaryDirectory() as scratch:
        # Isolated session-scratch base: without it the launcher
        # falls back to the shared per-uid /tmp base, where
        # concurrent launcher instances (parallel test workers,
        # live sessions on the same host) race the ownership/squat
        # checks and a losing racer exits non-zero — an
        # environment flake, not a scrub verdict. Tests probing
        # the scratch lane itself pass their own RAPTOR_WORK_DIR.
        env.setdefault("RAPTOR_WORK_DIR", scratch)
        return subprocess.run(
            ["bash", str(_LAUNCHER), "--help"],
            capture_output=True, text=True, timeout=60, env=env,
        )


class TestPathScrubWarningsEscaped(unittest.TestCase):
    def test_prepass_relative_entry_warning_stripped(self):
        proc = _run_help(f"rel{_HOSTILE}dir:/usr/bin:/bin")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("dropped unsafe PATH entry (relative entry)",
                      proc.stderr)
        self.assertNotIn("\x1b", proc.stderr)
        self.assertNotIn("\x07", proc.stderr)

    def test_prepass_keep_with_warning_stripped(self):
        proc = _run_help(
            f"rel{_HOSTILE}dir:/usr/bin:/bin",
            extra_env={"RAPTOR_ALLOW_UNSAFE_PATH": "1"},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("keeping unsafe PATH entry", proc.stderr)
        self.assertNotIn("\x1b", proc.stderr)
        self.assertNotIn("\x07", proc.stderr)

    def test_tmpdir_base_warning_stripped(self):
        """RAPTOR_WORK_DIR/TMPDIR feed the session-scratch base — the
        same attacker-influenceable env class as PATH; the
        not-owned-directory warning must not echo its raw bytes."""
        with tempfile.TemporaryDirectory() as d:
            work = Path(d) / f"w{_HOSTILE}k"
            base = work / f"raptor-{os.getuid()}"
            base.parent.mkdir(parents=True)
            base.symlink_to("/nonexistent")  # squat-check refusal path
            proc = _run_help(
                "/usr/bin:/bin",
                extra_env={"RAPTOR_WORK_DIR": str(work)},
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("session TMPDIR disabled", proc.stderr)
        self.assertNotIn("\x1b", proc.stderr)
        self.assertNotIn("\x07", proc.stderr)

    def test_full_scrub_world_writable_warning_stripped(self):
        with tempfile.TemporaryDirectory() as d:
            hostile_dir = Path(d) / f"ev{_HOSTILE}il"
            hostile_dir.mkdir()
            hostile_dir.chmod(hostile_dir.stat().st_mode
                              | stat.S_IWOTH | stat.S_IXOTH
                              | stat.S_IROTH)
            proc = _run_help(f"{hostile_dir}:/usr/bin:/bin")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("world-writable dir", proc.stderr)
        self.assertNotIn("\x1b", proc.stderr)
        self.assertNotIn("\x07", proc.stderr)


if __name__ == "__main__":
    unittest.main()
