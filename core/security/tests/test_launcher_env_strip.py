"""Launcher-side dangerous-env stripping — shared list, no drift.

Why this test exists
--------------------
The bash launchers strip code-injection env vars (LD_PRELOAD,
PYTHONSTARTUP, ...) BEFORE the Python interpreter boots. The strip
list is maintained once, in core/security/_dangerous_env_strip.sh;
launchers must SOURCE it, not carry their own copy. The drift this
guards against is real: bin/raptor-sca hand-rolled its own list and
silently missed the newer additions (LD_DEBUG / LD_PROFILE*,
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
# including the newer additions that drifted out of the hand-rolled
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


class TestExportedFunctionHardening(unittest.TestCase):
    """A hostile parent env can export bash FUNCTIONS
    (BASH_FUNC_<name>%% entries, imported at shell startup) that
    shadow the very builtins the strip fragment calls — pre-fix,
    shadowing `unset` both executed attacker code once per strip-loop
    iteration and silently neutralised the whole strip."""

    _FUNC_POISON = {
        "BASH_FUNC_unset%%": "() { echo PWNED-unset; }",
        "BASH_FUNC_command%%": "() { echo PWNED-command; }",
        "BASH_FUNC_declare%%": "() { echo PWNED-declare; }",
        "BASH_FUNC_read%%": "() { echo PWNED-read; }",
    }

    def _run_fragment(self) -> "subprocess.CompletedProcess[str]":
        # Source the fragment in a bash whose env imports the hostile
        # functions, then report what survived.
        script = (
            f'. "{REPO}/core/security/_dangerous_env_strip.sh"\n'
            'echo "LD_PRELOAD=${LD_PRELOAD:-<stripped>}"\n'
            'echo "POSIXLY_CORRECT=${POSIXLY_CORRECT:-<unset>}"\n'
            # Any surviving imported function would re-export into
            # children; declare -F must show no exported functions.
            'declare -F | grep -c "declare -fx" || true\n'
            'unset -v PROBE_OK 2>/dev/null; echo STRIP-RAN\n'
        )
        env = {
            "PATH": "/usr/bin:/bin",
            "LD_PRELOAD": "/tmp/evil.so",
            **self._FUNC_POISON,
        }
        return subprocess.run(
            ["bash", "-c", script],
            capture_output=True, text=True, timeout=60,
            env=env, check=False,
        )

    def test_strip_survives_builtin_shadowing(self):
        proc = self._run_fragment()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("PWNED", proc.stdout + proc.stderr,
                         "attacker function executed inside the strip")
        self.assertIn("LD_PRELOAD=<stripped>", proc.stdout,
                      "strip was neutralised by the unset shadow")
        self.assertIn("STRIP-RAN", proc.stdout)

    def test_imported_functions_swept(self):
        proc = self._run_fragment()
        # grep -c over `declare -F` output: zero exported functions
        # survive (the count line prints 0).
        self.assertIn("\n0\n", "\n" + proc.stdout,
                      f"exported functions survived: {proc.stdout!r}")

    def test_posix_mode_restored(self):
        proc = self._run_fragment()
        self.assertIn("POSIXLY_CORRECT=<unset>", proc.stdout,
                      "fragment leaked POSIX mode into the launcher")

    def test_preexisting_posix_mode_preserved(self):
        script = (
            f'. "{REPO}/core/security/_dangerous_env_strip.sh"\n'
            'echo "POSIXLY_CORRECT=${POSIXLY_CORRECT:-<unset>}"\n'
        )
        proc = subprocess.run(
            ["bash", "-c", script],
            capture_output=True, text=True, timeout=60,
            env={"PATH": "/usr/bin:/bin", "POSIXLY_CORRECT": "1"},
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("POSIXLY_CORRECT=1", proc.stdout)

    def test_fragment_works_under_strict_shell_options(self):
        # The launchers run with set -euo pipefail; the hardening must
        # not introduce a nonzero status that kills them.
        script = (
            "set -euo pipefail\n"
            f'. "{REPO}/core/security/_dangerous_env_strip.sh"\n'
            "echo STRICT-OK\n"
        )
        proc = subprocess.run(
            ["bash", "-c", script],
            capture_output=True, text=True, timeout=60,
            env={"PATH": "/usr/bin:/bin", **self._FUNC_POISON,
                 "LD_PRELOAD": "/tmp/evil.so"},
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("STRICT-OK", proc.stdout)


class TestPreSweepWindow(unittest.TestCase):
    """The launchers resolve RAPTOR_DIR BEFORE the strip fragment can
    be sourced, and every name that window calls — `set` itself
    (set -euo pipefail runs AFTER the sweep), `command` (a REGULAR
    builtin that functions precede even in POSIX mode, so command -p
    pinning alone is not protection), and the resolution helpers —
    is shadowable by an exported function. The inline pre-sweep
    (POSIX-mode special-builtin bootstrap + exported-function drop)
    must be the first executable block in BOTH launchers."""

    _NAMES = ("set", "command", "dirname", "readlink", "cd", "pwd",
              "unset", "echo", "read", "declare", "test", "trap")

    def _probe(self, rel_script: str, arg: str, shadows: dict) -> str:
        proc = subprocess.run(
            ["bash", str(REPO / rel_script), arg],
            capture_output=True, text=True, timeout=60,
            env={"PATH": "/usr/bin:/bin",
                 "HOME": os.environ.get("HOME", "/tmp"),
                 **shadows},
        )
        return proc.stdout + proc.stderr

    def test_shadow_battery_both_launchers(self):
        for rel, arg in (("bin/cve-diff", "--help"),
                         ("bin/raptor", "--version")):
            for name in self._NAMES:
                with self.subTest(launcher=rel, shadow=name):
                    out = self._probe(rel, arg, {
                        f"BASH_FUNC_{name}%%":
                            "() { /bin/echo PWNED-" + name + " >&2; exit 9; }",
                    })
                    self.assertNotIn("PWNED", out)

    def test_simultaneous_shadows_both_launchers(self):
        shadows = {
            f"BASH_FUNC_{n}%%":
                "() { /bin/echo PWNED-" + n + " >&2; exit 9; }"
            for n in self._NAMES
        }
        for rel, arg in (("bin/cve-diff", "--help"),
                         ("bin/raptor", "--version")):
            self.assertNotIn("PWNED", self._probe(rel, arg, shadows), rel)

    def test_presweep_precedes_set_and_resolution(self):
        # Static pin: the sweep must precede `set -euo pipefail` AND
        # the path resolution — `set` is function-shadowable, so
        # nothing executable may come before the sweep (markers are
        # executable lines, not comment mentions).
        for rel in ("bin/raptor", "bin/cve-diff"):
            text = (REPO / rel).read_text(encoding="utf-8")
            sweep = text.index("_raptor_presweep_posix=")
            for marker in ("\nset -euo pipefail\n", '\nSCRIPT="$0"',
                           '\nRAPTOR_DIR="$('):
                self.assertLess(sweep, text.index(marker),
                                f"{rel}: {marker.strip()} precedes the pre-sweep")

    def test_presweep_lines_are_errexit_safe(self):
        # The sweep runs without -e, but every fallible line must
        # still carry a guard so a future reorder under -e cannot
        # abort the launcher: each `unset -f`/cleanup line ends || :.
        for rel in ("bin/raptor", "bin/cve-diff"):
            text = (REPO / rel).read_text(encoding="utf-8")
            block = text[text.index("_raptor_presweep_posix="):
                         text.index("\nset -euo pipefail\n")]
            for line in block.splitlines():
                stripped = line.strip()
                if stripped.startswith("unset ") and "POSIXLY_CORRECT" not in stripped:
                    self.assertTrue(
                        stripped.endswith("|| :"),
                        f"{rel}: unguarded sweep line: {stripped!r}")

    def test_clean_env_unaffected(self):
        # Hermetic: python-side deps may be absent on a CI runner, so
        # assert the bash window (sweep + resolution + strip) ran
        # clean rather than demanding the python CLI succeeds.
        proc = subprocess.run(
            ["bash", str(REPO / "bin/cve-diff"), "--help"],
            capture_output=True, text=True, timeout=60,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                 "HOME": os.environ.get("HOME", "/tmp")},
        )
        combined = proc.stdout + proc.stderr
        self.assertNotIn("cannot find RAPTOR installation", combined)
        self.assertNotIn("symlink hop limit", combined)
        self.assertNotIn("bin/cve-diff: line", combined)

    def test_preexisting_posix_mode_preserved(self):
        proc = subprocess.run(
            ["bash", "-c",
             f'export POSIXLY_CORRECT=1; bash "{REPO}/bin/cve-diff" --help'
             ' >/dev/null 2>&1; echo "posix=${POSIXLY_CORRECT:-unset}"'],
            capture_output=True, text=True, timeout=60,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                 "HOME": os.environ.get("HOME", "/tmp")},
        )
        self.assertIn("posix=1", proc.stdout)
