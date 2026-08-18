"""Launcher-side dangerous-env stripping — shared list, no drift.

Why this test exists
--------------------
The bash launchers strip code-injection env vars (LD_PRELOAD,
PYTHONSTARTUP, ...) BEFORE the Python interpreter boots. The strip
list is maintained once, in core/security/_dangerous_env_strip.sh;
launchers must SOURCE it, not carry their own copy. The drift this
guards against is real: bin/raptor-sca hand-rolled its own list and
silently missed the batch-581 additions (LD_DEBUG / LD_PROFILE*,
MALLOC_*, NODE_*, DYLD_FALLBACK_LIBRARY_PATH), and
libexec/raptor-llm-scorecard exec'd python3 with the caller's full
environment.

Two layers:

* static — every python-exec'ing bash entry point sources the shared
  fragment;
* behavioural — running the wrapper with a poisoned environment and a
  stub python3 on PATH shows the dangerous vars never reach the child.
"""

from __future__ import annotations

import os
import stat
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

_SOURCED_FRAGMENT = "_dangerous_env_strip.sh"

# Bash entry points that exec python3 and may be invoked with a hostile
# parent environment (operator shells, ~/bin symlinks).
_BASH_ENTRY_POINTS = (
    "bin/raptor",
    "bin/cve-diff",
    "bin/raptor-sca",
    "libexec/raptor-llm-scorecard",
)

# One representative from each family the shared fragment strips,
# including the batch-581 additions that drifted out of the hand-rolled
# copies.
_POISON = {
    "LD_PRELOAD": "/tmp/evil.so",
    "LD_DEBUG": "all",
    "LD_PROFILE": "libc.so.6",
    "DYLD_FALLBACK_LIBRARY_PATH": "/tmp/evil",
    "PYTHONSTARTUP": "/tmp/evil.py",
    "NODE_OPTIONS": "--require /tmp/evil.js",
    "MALLOC_CONF": "prof:true,prof_prefix:/tmp/x",
    "BASH_ENV": "/tmp/evil.sh",
}


class TestStaticSharedList(unittest.TestCase):
    def test_entry_points_source_the_shared_fragment(self):
        for rel in _BASH_ENTRY_POINTS:
            with self.subTest(script=rel):
                text = (REPO / rel).read_text(encoding="utf-8")
                self.assertIn(
                    _SOURCED_FRAGMENT,
                    text,
                    f"{rel} does not source the shared strip fragment",
                )

    def test_no_hand_rolled_strip_lists(self):
        # A literal LD_PRELOAD in an entry point means a private strip
        # list crept back in (the shared fragment is the only home).
        for rel in _BASH_ENTRY_POINTS:
            with self.subTest(script=rel):
                text = (REPO / rel).read_text(encoding="utf-8")
                self.assertNotIn(
                    "LD_PRELOAD",
                    text,
                    f"{rel} carries its own strip list; source "
                    f"{_SOURCED_FRAGMENT} instead",
                )

    def test_scorecard_wrapper_hardened(self):
        text = (REPO / "libexec/raptor-llm-scorecard").read_text(
            encoding="utf-8"
        )
        self.assertIn("set -euo pipefail", text)
        self.assertIn("_symhops", text, "missing bounded symlink walk")


class TestBehaviouralStrip(unittest.TestCase):
    """Poisoned env + stub python3: dangerous vars must not reach it."""

    def _run_with_stub(self, rel_script: str, extra_env: dict) -> str:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            stub = Path(td) / "python3"
            stub.write_text("#!/bin/sh\nenv\n", encoding="utf-8")
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
            env = {
                "PATH": f"{td}:/usr/bin:/bin",
                "HOME": os.environ.get("HOME", td),
                "_RAPTOR_TRUSTED": "1",
                **_POISON,
                **extra_env,
            }
            proc = subprocess.run(
                ["bash", str(REPO / rel_script)],
                capture_output=True,
                text=True,
                timeout=60,
                env=env,
                cwd=td,
                check=False,
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"{rel_script} failed under stub python3: {proc.stderr}",
            )
            return proc.stdout

    def test_raptor_sca_strips_dangerous_env(self):
        out = self._run_with_stub(
            "bin/raptor-sca", {"PYTHONWARNINGS": "all"}
        )
        for var in _POISON:
            self.assertNotIn(f"{var}=", out, f"{var} leaked through")
        # raptor-sca additionally strips the whole PYTHON* family.
        self.assertNotIn("PYTHONWARNINGS=", out)

    def test_llm_scorecard_strips_dangerous_env(self):
        out = self._run_with_stub("libexec/raptor-llm-scorecard", {})
        for var in _POISON:
            self.assertNotIn(f"{var}=", out, f"{var} leaked through")


if __name__ == "__main__":
    unittest.main()
