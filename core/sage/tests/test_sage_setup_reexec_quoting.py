#!/usr/bin/env python3
"""sg-docker re-exec quoting in libexec/raptor-sage-setup.

Same contract as the raptor-sage-mcp sibling (whose comment names the
naive-interpolation bug): ``sg -c`` takes a single shell string, and
``"\\"$0\\""`` interpolation breaks on an install path carrying a
quote or ``$``. The re-exec must quote with ``printf %q`` and forward
the original arguments verbatim.

Hermetic: stub ``docker`` (fails ``info``) and ``sg`` (records the
command string) on PATH — no real docker, no container, no network.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SETUP = REPO_ROOT / "libexec" / "raptor-sage-setup"

# `compose version` must succeed (plugin-present check precedes the
# daemon probe); `info` fails so the sg re-exec path engages.
DOCKER_STUB = """#!/bin/sh
case "$1" in
  compose) exit 0 ;;
  *) exit 1 ;;
esac
"""

# $3 is the single command string sg -c receives; "docker info" is the
# script's does-sg-fix-it probe, everything else is the re-exec.
SG_STUB = """#!/bin/sh
if [ "$3" = "docker info" ]; then exit 0; fi
printf '%s' "$3" > "$SG_CAPTURE"
exit 0
"""


@unittest.skipIf(shutil.which("jq") is None,
                 "jq required (install path runs `need jq` first)")
class TestSgReExecQuoting(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.bindir = self.dir / "bin"
        self.bindir.mkdir()
        for name, body in (("docker", DOCKER_STUB), ("sg", SG_STUB)):
            path = self.bindir / name
            path.write_text(body, encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.capture = self.dir / "sg-capture"

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, script: Path, *args: str):
        env = dict(os.environ)
        env["PATH"] = f"{self.bindir}:{env.get('PATH', '')}"
        env["SG_CAPTURE"] = str(self.capture)
        env["CLAUDECODE"] = "1"
        return subprocess.run(
            [str(script), *args], input="",
            capture_output=True, text=True, env=env, timeout=60,
        )

    def _expected(self, script: Path, *args: str) -> str:
        out = subprocess.run(
            ["bash", "-c", 'printf "%q " "$@"', "_", str(script), *args],
            capture_output=True, text=True, check=True,
        )
        return out.stdout

    def test_reexec_string_roundtrips(self):
        proc = self._run(SETUP, "install")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.capture.read_text(),
                         self._expected(SETUP, "install"))

    def test_quoted_install_path_survives(self):
        """An install path carrying a quote and a space must round-trip
        — the naive interpolation produced a broken shell string."""
        hostile_dir = self.dir / 'qu"ote dir'
        hostile_dir.mkdir()
        link = hostile_dir / "raptor-sage-setup"
        link.symlink_to(SETUP)
        proc = self._run(link, "install")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        cmd = self.capture.read_text()
        self.assertEqual(cmd, self._expected(link, "install"))
        # Round-trip: eval-ing the string yields the original argv.
        echo = subprocess.run(
            ["bash", "-c", f'set -- {cmd}; printf "%s\\n" "$@"'],
            capture_output=True, text=True,
        )
        self.assertEqual(echo.stdout.splitlines(),
                         [str(link), "install"])


if __name__ == "__main__":
    unittest.main()
