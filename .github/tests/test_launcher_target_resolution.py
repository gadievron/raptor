"""An unresolvable target must refuse loudly, never die silently.

Why this test exists
--------------------
``bin/raptor`` vets an explicit target by resolving it with
``CHECK_TARGET="$(cd "$_target_clean" && pwd)"`` after an ``[ -d ]``
test. ``-d`` passes on a readable directory the user cannot traverse
(no execute bit), and the directory can vanish between test and cd —
either way the substitution fails, and under ``set -euo pipefail``
the statement-level assignment killed the launcher with only cd's
terse stderr. The lane must instead refuse with a launcher-owned,
length-bounded message, and must still refuse (an unresolvable
target cannot be vetted or scanned) — fail-closed, but loud.

The case plants a fake ``claude`` on PATH so the launcher passes its
presence check without any risk of launching a real session: the
refusal exits before the exec, and the sentinel output proves the
fake was never run. HOME is pointed into the sandbox so no real
session state is touched on any path.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO / "bin" / "raptor"


class TestTargetResolutionRefusesLoudly(unittest.TestCase):
    def test_non_traversable_target_refuses_with_message(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root ignores directory mode bits; cd cannot fail")
        with tempfile.TemporaryDirectory() as d:
            fakebin = Path(d) / "bin"
            fakebin.mkdir()
            fake_claude = fakebin / "claude"
            fake_claude.write_text("#!/bin/sh\necho FAKE-CLAUDE-RAN\nexit 97\n")
            fake_claude.chmod(0o755)
            work = Path(d) / "work"
            work.mkdir()
            target = Path(d) / "noexec"
            target.mkdir()
            target.chmod(0o644)
            try:
                proc = subprocess.run(
                    ["bash", str(_LAUNCHER), str(target)],
                    capture_output=True, text=True, timeout=60,
                    env={
                        "HOME": d,
                        "PATH": f"{fakebin}:/usr/bin:/bin",
                        "RAPTOR_WORK_DIR": str(work),
                    },
                )
            finally:
                target.chmod(0o755)
        combined = proc.stdout + proc.stderr
        self.assertNotIn("FAKE-CLAUDE-RAN", combined,
                         "launcher reached exec despite unresolvable target")
        self.assertEqual(proc.returncode, 1, combined)
        self.assertIn("cannot resolve target directory", proc.stderr)


if __name__ == "__main__":
    unittest.main()
