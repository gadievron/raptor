"""bin/raptor refuses a PATH python3 that lacks RAPTOR's dependencies.

The launcher keeps standard PATH resolution for python3. When the
resolved interpreter is not the one RAPTOR was installed into, the
session launch stops before startup-check and names the environment
to activate.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO / "bin" / "raptor"
_MESSAGE = "is missing RAPTOR's Python dependencies"
_CLAUDE_MARKER = "fake-claude-reached"


def _write_exe(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)


def _launch(with_deps: bool):
    """Launch a session with a stub claude. python3 is either the test
    interpreter or a fresh venv that has only the standard library."""
    with tempfile.TemporaryDirectory() as scratch:
        base = Path(scratch)
        bindir = base / "bin"
        bindir.mkdir()
        if with_deps:
            _write_exe(bindir / "python3", f'exec "{sys.executable}" "$@"')
        else:
            subprocess.run(
                [sys.executable, "-m", "venv", "--without-pip",
                 str(base / "bare")], check=True)
            (bindir / "python3").symlink_to(base / "bare" / "bin" / "python3")
        _write_exe(bindir / "claude", f"echo {_CLAUDE_MARKER}")
        caller = base / "caller"
        caller.mkdir()
        env = {
            "HOME": str(base),
            "PATH": f"{bindir}:/usr/bin:/bin",
            "RAPTOR_WORK_DIR": str(base / "work"),
        }
        result = subprocess.run(
            ["bash", str(_LAUNCHER)],
            capture_output=True, text=True, timeout=60, env=env,
            cwd=caller, stdin=subprocess.DEVNULL,
        )
        return result, bindir / "python3"


class LauncherPythonDepsTest(unittest.TestCase):

    def test_python_without_deps_is_refused_with_the_fix(self):
        result, python3 = _launch(with_deps=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"{python3} {_MESSAGE}", result.stderr)
        self.assertIn("source ", result.stderr)
        self.assertNotIn(_CLAUDE_MARKER, result.stdout)

    def test_python_with_deps_reaches_the_session(self):
        result, _ = _launch(with_deps=True)
        self.assertNotIn(_MESSAGE, result.stderr)
        self.assertIn(_CLAUDE_MARKER, result.stdout, result.stderr)


if __name__ == "__main__":
    unittest.main()
