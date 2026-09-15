"""Display integrity of the startup-check mismatch menu.

The mismatch prompt decides which project binds the session — an
authorization surface. Project names are charset-constrained at
create time, but target PATHS are not (adopted and machine-created
``corpus-*`` targets are external input): a path carrying terminal
controls must reach the operator's TTY escaped, not raw.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-startup-check"

# ESC[2A cursor-up + erase-line: enough to forge a different menu had
# it reached the terminal raw.
HOSTILE_SEGMENT = "evil-\x1b[2A\x1b[K-dir"


class TestMismatchMenuDisplay(unittest.TestCase):
    def test_mismatch_menu_escapes_target_paths(self):
        from core.project import ProjectManager

        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "home"
            home.mkdir()
            hostile_target = root / HOSTILE_SEGMENT
            hostile_target.mkdir()
            caller = root / "caller-project"
            caller.mkdir()

            mgr = ProjectManager(projects_dir=home / ".raptor" / "projects")
            mgr.create("proja", str(hostile_target),
                       output_dir=str(root / "out" / "proja"))
            mgr.create("projb", str(caller),
                       output_dir=str(root / "out" / "projb"))
            mgr.set_active("proja")

            env = dict(os.environ)
            env["HOME"] = str(home)
            env["_RAPTOR_TRUSTED"] = "1"
            proc = subprocess.run(
                [sys.executable, str(SCRIPT),
                 "--caller-dir", str(caller)],
                capture_output=True, text=True, timeout=60,
                env=env, stdin=subprocess.DEVNULL,
                cwd=str(REPO_ROOT),
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            # The menu fired (non-TTY stdin defaults to choice 1).
            self.assertIn("Last-activated project is proja", proc.stderr)
            # No raw ESC anywhere on the operator-facing stream.
            self.assertNotIn("\x1b", proc.stderr,
                             "raw ESC reached the mismatch menu")
            # Escaped, reviewable spelling instead — for both the
            # active target and the caller-dir render slots.
            self.assertIn("\\x1b[2a".lower(), proc.stderr.lower())
            self.assertIn("caller-project", proc.stderr)
            # The machine contract survives.
            self.assertIn("RAPTOR_SEEDED_BY=bookmark", proc.stdout)
            self.assertIn("RAPTOR_RESOLVED_PROJECT=proja", proc.stdout)


if __name__ == "__main__":
    unittest.main()
