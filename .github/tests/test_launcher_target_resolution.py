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

Resolution must also ignore the operator's ``CDPATH``: a CDPATH
entry (hostile-direnv env class, not covered by the env strip) makes
a bare ``cd`` prefer the CDPATH base over the shell cwd for a
relative target — the gate would vet a different directory than the
session scans — and print the resolved dir into the substitution.

The cases plant a fake ``claude`` on PATH so the launcher passes its
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


def _sandbox(d: str) -> dict[str, str]:
    """Env + fake-claude scaffolding shared by the cases."""
    fakebin = Path(d) / "bin"
    fakebin.mkdir()
    fakebin.chmod(0o755)  # umask-proof: a 0777 dir would be scrubbed off PATH
    fake_claude = fakebin / "claude"
    fake_claude.write_text("#!/bin/sh\necho FAKE-CLAUDE-RAN\nexit 97\n")
    fake_claude.chmod(0o755)
    work = Path(d) / "work"
    work.mkdir()
    return {
        "HOME": d,
        "PATH": f"{fakebin}:/usr/bin:/bin",
        "RAPTOR_WORK_DIR": str(work),
    }


class TestTargetResolutionRefusesLoudly(unittest.TestCase):
    def test_non_traversable_target_refuses_with_message(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root ignores directory mode bits; cd cannot fail")
        with tempfile.TemporaryDirectory() as d:
            env = _sandbox(d)
            target = Path(d) / "noexec"
            target.mkdir()
            target.chmod(0o644)
            try:
                proc = subprocess.run(
                    ["bash", str(_LAUNCHER), str(target)],
                    capture_output=True, text=True, timeout=60, env=env,
                )
            finally:
                target.chmod(0o755)
        combined = proc.stdout + proc.stderr
        self.assertNotIn("FAKE-CLAUDE-RAN", combined,
                         "launcher reached exec despite unresolvable target")
        self.assertEqual(proc.returncode, 1, combined)
        self.assertIn("cannot resolve target directory", proc.stderr)

    def test_cdpath_cannot_redirect_target_resolution(self) -> None:
        """A CDPATH decoy holding a traversable dir of the same name
        must not rescue (and silently redirect) the resolution of a
        relative target the shell cwd cannot traverse: the launch
        must still refuse on the cwd-relative path."""
        if os.geteuid() == 0:
            self.skipTest("root ignores directory mode bits; cd cannot fail")
        with tempfile.TemporaryDirectory() as d:
            env = _sandbox(d)
            env["CDPATH"] = str(Path(d) / "decoy")
            (Path(d) / "decoy" / "proj").mkdir(parents=True)
            cwd = Path(d) / "cwd"
            real = cwd / "proj"
            real.mkdir(parents=True)
            real.chmod(0o644)
            try:
                proc = subprocess.run(
                    ["bash", str(_LAUNCHER), "proj"],
                    capture_output=True, text=True, timeout=60,
                    env=env, cwd=str(cwd),
                )
            finally:
                real.chmod(0o755)
        combined = proc.stdout + proc.stderr
        self.assertNotIn("FAKE-CLAUDE-RAN", combined,
                         "CDPATH redirected target resolution to the decoy")
        self.assertEqual(proc.returncode, 1, combined)
        self.assertIn("cannot resolve target directory", proc.stderr)


if __name__ == "__main__":
    unittest.main()
