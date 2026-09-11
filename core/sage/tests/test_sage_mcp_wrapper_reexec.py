#!/usr/bin/env python3
"""sg-docker re-exec quoting in libexec/raptor-sage-mcp.

The wrapper re-execs itself under ``sg docker -c <string>`` when the
docker socket needs group membership. ``sg -c`` takes a single shell
string, and the old naive ``"\\"$0\\""`` interpolation broke on install
paths carrying a quote or ``$`` and silently dropped any arguments.
The re-exec now quotes with ``printf %q`` and forwards ``"$@"``.

Hermetic: stub ``docker`` (fails ``info``) and ``sg`` (records the
command string) on PATH — no real docker, no container, no network.
"""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
WRAPPER = REPO_ROOT / "libexec" / "raptor-sage-mcp"

DOCKER_STUB = """#!/bin/sh
case "$1" in
  compose) exit 0 ;;
  *) exit 1 ;;
esac
"""

# $3 is the single command string sg -c receives; "docker info" is the
# wrapper's does-sg-fix-it probe, everything else is the re-exec.
SG_STUB = """#!/bin/sh
if [ "$3" = "docker info" ]; then exit 0; fi
printf '%s' "$3" > "$SG_CAPTURE"
exit 0
"""


class TestSgReExec(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
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

    def _run(self, *args: str):
        env = dict(os.environ)
        env["PATH"] = f"{self.bindir}:{env.get('PATH', '')}"
        env["SG_CAPTURE"] = str(self.capture)
        env["CLAUDECODE"] = "1"
        # Never arm the capture bypass from a test environment.
        env.pop("RAPTOR_SAGE_BOOT_CAPTURE", None)
        return subprocess.run(
            [str(WRAPPER), *args], input="",
            capture_output=True, text=True, env=env, timeout=60,
        )

    def _expected(self, *args: str) -> str:
        # The same %q rendering bash produces for these words.
        out = subprocess.run(
            ["bash", "-c", 'printf "%q " "$@"', "_", str(WRAPPER), *args],
            capture_output=True, text=True, check=True,
        )
        return out.stdout

    def test_zero_arg_reexec_carries_the_script_path(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.capture.read_text(), self._expected())

    def test_args_are_forwarded_and_shell_safe(self):
        """Arguments — including ones a naive quote would mangle —
        survive the re-exec verbatim."""
        args = ["--flag", "a b", 'quo"te$HOME']
        proc = self._run(*args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        cmd = self.capture.read_text()
        self.assertEqual(cmd, self._expected(*args))
        # Round-trip: eval-ing the string yields the original argv.
        echo = subprocess.run(
            ["bash", "-c",
             f'set -- {cmd}; shift; printf "%s\\n" "$@"'],
            capture_output=True, text=True,
        )
        self.assertEqual(echo.stdout.splitlines(), args)


if __name__ == "__main__":
    unittest.main()
