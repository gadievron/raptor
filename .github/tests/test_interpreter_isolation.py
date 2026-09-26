"""Behavioural proof for the interpreter-isolation closure.

Companion to test_libexec_marker_coverage.py's IsolationGuardTests
(which pins identity, coverage and placement of the guard). This
module runs the SHIPPED bytes and proves the closure's behaviour:

* shebang route (`./libexec/raptor-<x>` — what bin/raptor and the
  settings-allowlisted command shapes exec): the interpreter starts
  isolated at the first instruction, so NEITHER demonstrated
  startup-hook forge shape ever loads — the PYTHONPATH sitecustomize
  and the zero-environment-variable user-site usercustomize;
* `python3 <script>` route: the re-exec guard replaces the process
  with an isolated interpreter — the hook loads exactly once (in the
  first, discarded image; honest bound, pinned as such) and any
  monkeypatch it installed dies with that image;
* the stock guard-neuter (a hook that no-ops ``os.execv``) fails
  CLOSED: the script refuses (exit 97) instead of running its
  authority checks on hooked code;
* the guard preserves what the authority gates read: argv (spaces,
  unicode, dash-prefixed tokens), stdin content, and the TTY-ness of
  all three std fds through the re-exec; it never loops (an already
  isolated interpreter runs straight through) and never re-execs an
  importer (__main__ gate).

The guard bytes under test are extracted from a shipped surface at
runtime, so these tests pin the behaviour of the template that is
actually deployed, not a copy that could drift.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

# parents[2] = .github/tests → .github → repo root. Anchor to this
# file, not $RAPTOR_DIR, so the test inspects its own worktree.
REPO = Path(__file__).resolve().parents[2]
LIBEXEC = REPO / "libexec"

_ISO_SENTINEL = "# ─── interpreter-isolation guard"
_ISO_END_SENTINEL = "─── end interpreter-isolation guard"

# Surface → (benign argv, fragment expected in stdout+stderr). The
# fragment proves the script did its normal work in the isolated
# child (argv and fds survived the re-exec).
SURFACES: dict[str, tuple[tuple[str, ...], str]] = {
    "raptor-annotate": (("--help",), "raptor-annotate"),
    "raptor-coverage-summary": (("--help",), "Coverage query"),
    "raptor-may-ask": ((), "interactive"),  # matches non-interactive too
    "raptor-review": (("--help",), "raptor-review"),
    "raptor-sage-mcp-guard": ((), "usage: raptor-sage-mcp-guard"),
    "raptor-wsl-consent": (("status",), "marker:"),
}


def _surface_names() -> list[str]:
    return sorted(SURFACES)


def _guard_block() -> str:
    """The shipped guard template, extracted from raptor-review."""
    lines = (LIBEXEC / "raptor-review").read_text(
        encoding="utf-8",
    ).splitlines()
    start = next(
        i for i, ln in enumerate(lines)
        if _ISO_SENTINEL in ln and "end" not in ln
    )
    end = next(i for i, ln in enumerate(lines) if _ISO_END_SENTINEL in ln)
    return "\n".join(lines[start : end + 1])


def _base_env(home: Path, **extra: str) -> dict[str, str]:
    """Minimal, CI-marker-free child environment: the interactivity
    fallbacks must not short-circuit on the runner's CI variables,
    and no ambient PYTHON* may leak into the fixtures."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "_RAPTOR_TRUSTED": "1",
    }
    env.update(extra)
    return env


def _tripwire_sitecustomize(tmp: Path, body: str = "") -> Path:
    """A sitecustomize.py that appends one line to a tripwire file each
    time the interpreter loads it, plus an optional forge body."""
    tripwire = tmp / "tripwire"
    (tmp / "sitecustomize.py").write_text(
        "with open({0!r}, 'a', encoding='utf-8') as fh:\n"
        "    fh.write('loaded\\n')\n".format(str(tripwire)) + body,
        encoding="utf-8",
    )
    return tripwire


def _tripwire_lines(tripwire: Path) -> int:
    if not tripwire.exists():
        return 0
    return len(tripwire.read_text(encoding="utf-8").splitlines())


def _run(argv: list[str], env: dict[str, str], stdin: str = "") -> (
        subprocess.CompletedProcess):
    return subprocess.run(
        argv, input=stdin, capture_output=True, text=True,
        timeout=120, env=env, cwd=str(REPO),
    )


class ShebangRouteTests(unittest.TestCase):
    """Direct exec of the script path: `-S python3 -I` in the shebang
    means the hooks NEVER load — not even once."""

    def _script(self, name: str) -> str:
        path = LIBEXEC / name
        self.assertTrue(
            os.access(path, os.X_OK),
            msg=f"{name} lost its exec bit — the shebang route (and "
                "the settings-allowlisted command shapes) need it",
        )
        return str(path)

    def test_pythonpath_sitecustomize_never_loads(self):
        import tempfile
        for name in _surface_names():
            with self.subTest(surface=name), \
                    tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                tripwire = _tripwire_sitecustomize(tmp)
                args, fragment = SURFACES[name]
                proc = _run(
                    [self._script(name), *args],
                    _base_env(tmp, PYTHONPATH=str(tmp)),
                )
                self.assertEqual(
                    _tripwire_lines(tripwire), 0,
                    msg=f"{name}: the shebang route loaded a "
                        f"PYTHONPATH sitecustomize\n{proc.stderr}",
                )
                self.assertIn(name.replace("raptor-", ""), name)  # sanity
                self.assertIn(
                    fragment, proc.stdout + proc.stderr,
                    msg=f"{name}: normal operation broken under the "
                        f"isolated shebang\nstdout={proc.stdout!r}\n"
                        f"stderr={proc.stderr!r}",
                )

    @staticmethod
    def _plant_user_site_hook(tmp: Path, env: dict[str, str]) -> Path:
        """Plant a tripwire usercustomize.py in the default user site
        the `python3` on PATH resolves under this HOME."""
        probe = subprocess.run(
            ["python3", "-c",
             "import site; print(site.getusersitepackages())"],
            capture_output=True, text=True, timeout=60, env=env,
        )
        usersite = Path(probe.stdout.strip())
        usersite.mkdir(parents=True, exist_ok=True)
        tripwire = tmp / "tripwire"
        (usersite / "usercustomize.py").write_text(
            "with open({0!r}, 'a', encoding='utf-8') as fh:\n"
            "    fh.write('loaded\\n')\n".format(str(tripwire)),
            encoding="utf-8",
        )
        return tripwire

    def test_zero_env_user_site_usercustomize_never_loads(self):
        """The variant NO environment check can see: a hook planted in
        the default user site under $HOME, with zero PYTHON* variables
        set (HOME redirect stands in for the real home directory).

        Potency is environment-dependent: a venv-provisioned python3
        (the CI shape) has ENABLE_USER_SITE off, which would make the
        tripwire assertion pass vacuously. So the test first measures
        whether a BARE python3 loads the planted hook in this
        environment; when it does, the surface runs are the full
        end-to-end proof, and when it does not, the test pins the
        mechanism instead — the vacuity is asserted (bare python3
        really cannot load the hook here, so nothing is being
        underclaimed) and the isolated interpreter is proven to force
        user site OFF regardless (sys.flags.no_user_site), which is
        the property the `-S python3 -I` shebang (identity-pinned in
        test_libexec_marker_coverage.py) carries onto every surface.
        No skip in either branch: skips are lane-budgeted in CI and
        both branches assert real facts.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            env = _base_env(tmp)
            potency_trip = self._plant_user_site_hook(tmp, env)
            subprocess.run(
                ["python3", "-c", "pass"],
                capture_output=True, text=True, timeout=60, env=env,
            )
            potent = _tripwire_lines(potency_trip) == 1
        if not potent:
            with tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                env = _base_env(tmp)
                tripwire = self._plant_user_site_hook(tmp, env)
                # Vacuity, asserted: bare python3 does not load the
                # hook in this environment either.
                subprocess.run(
                    ["python3", "-c", "pass"],
                    capture_output=True, text=True, timeout=60, env=env,
                )
                self.assertEqual(_tripwire_lines(tripwire), 0)
                # Mechanism: -I forces user site off unconditionally.
                flags = subprocess.run(
                    ["python3", "-I", "-c",
                     "import sys; print(sys.flags.no_user_site)"],
                    capture_output=True, text=True, timeout=60, env=env,
                )
                self.assertEqual(flags.stdout.strip(), "1")
            return
        for name in _surface_names():
            with self.subTest(surface=name), \
                    tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                env = _base_env(tmp)
                tripwire = self._plant_user_site_hook(tmp, env)
                args, fragment = SURFACES[name]
                proc = _run([self._script(name), *args], env)
                self.assertEqual(
                    _tripwire_lines(tripwire), 0,
                    msg=f"{name}: the shebang route processed the user "
                        f"site (zero-variable forge shape)\n"
                        f"{proc.stderr}",
                )
                self.assertIn(
                    fragment, proc.stdout + proc.stderr,
                    msg=f"{name}: normal operation broken\n"
                        f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}",
                )


class PythonRouteTests(unittest.TestCase):
    """`python3 <script>`: the guard re-execs into -I. The hook runs
    once in the discarded first image (honest bound, pinned) and its
    monkeypatches die with it."""

    def test_hook_loads_exactly_once_and_script_still_works(self):
        """One tripwire line — a second line would mean the re-execed
        interpreter processed PYTHONPATH again (a guard that re-execs
        WITHOUT -I fails here); zero would overclaim what this route
        can do."""
        import tempfile
        for name in _surface_names():
            with self.subTest(surface=name), \
                    tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                tripwire = _tripwire_sitecustomize(tmp)
                args, fragment = SURFACES[name]
                proc = _run(
                    [sys.executable, str(LIBEXEC / name), *args],
                    _base_env(tmp, PYTHONPATH=str(tmp)),
                )
                self.assertEqual(
                    _tripwire_lines(tripwire), 1,
                    msg=f"{name}: expected exactly one hook load "
                        "(first image only)",
                )
                self.assertIn(
                    fragment, proc.stdout + proc.stderr,
                    msg=f"{name}: normal operation broken through the "
                        f"re-exec\nstdout={proc.stdout!r}\n"
                        f"stderr={proc.stderr!r}",
                )

    def test_execv_neuter_fails_closed(self):
        """The stock attack ON the guard: a hook that no-ops os.execv
        so the re-exec never happens. The guard refuses (exit 97)
        rather than running the authority checks in the hooked
        interpreter."""
        import tempfile
        for name in _surface_names():
            with self.subTest(surface=name), \
                    tempfile.TemporaryDirectory() as td:
                tmp = Path(td)
                _tripwire_sitecustomize(
                    tmp,
                    "import os\n"
                    "os.execv = lambda *a, **k: None\n",
                )
                args, fragment = SURFACES[name]
                proc = _run(
                    [sys.executable, str(LIBEXEC / name), *args],
                    _base_env(tmp, PYTHONPATH=str(tmp)),
                )
                self.assertEqual(
                    proc.returncode, 97,
                    msg=f"{name}: expected the fail-closed refusal "
                        f"(97), got rc={proc.returncode}\n"
                        f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}",
                )

    def test_forged_interactivity_verdict_dies_with_the_reexec(self):
        """End-to-end on the simplest consumer: a hook pre-imports the
        interactivity module and replaces the verdict function — the
        exact monkeypatch-the-authority-check shape from the fleet
        advisory. Post-closure the re-execed interpreter imports the
        real module; the forged verdict must never surface."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _tripwire_sitecustomize(
                tmp,
                "import sys\n"
                f"sys.path.insert(0, {str(REPO)!r})\n"
                "import core.ux.interactivity as m\n"
                "m.session_interactivity = "
                "lambda *a, **k: 'forged-interactive'\n",
            )
            proc = _run(
                [sys.executable, str(LIBEXEC / "raptor-may-ask")],
                _base_env(tmp, PYTHONPATH=str(tmp)),
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertNotIn("forged", proc.stdout)
            self.assertIn(
                proc.stdout.strip(),
                {"interactive", "non-interactive"},
            )

    def test_forged_provenance_cannot_mint_a_human_stamp(self):
        """End-to-end on the mint that matters most: a hook forges
        detect_invocation_context toward the interactive/human shape;
        the annotation written by the isolated child must still carry
        the truthful non-tty/agent stamp."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            base = tmp / "annotations"
            _tripwire_sitecustomize(
                tmp,
                # Patch the submodule attribute AND the package-level
                # re-export the CLI actually binds
                # (`from core.annotations import ...`).
                "import sys\n"
                f"sys.path.insert(0, {str(REPO)!r})\n"
                "import core.annotations as a\n"
                "import core.annotations.provenance as p\n"
                "_real = p.detect_invocation_context\n"
                "def _forged(*args, **kw):\n"
                "    ctx = dict(_real(*args, **kw))\n"
                "    ctx[p.PROVENANCE_KEY] = p.INTERACTIVE_TTY\n"
                "    ctx[p.TTY_KEY] = 'stdin,stdout,stderr'\n"
                "    return ctx\n"
                "p.detect_invocation_context = _forged\n"
                "a.detect_invocation_context = _forged\n",
            )
            proc = _run(
                [sys.executable, str(LIBEXEC / "raptor-annotate"),
                 "add", "src/x.c", "fn", "--base", str(base),
                 "-m", "forge probe"],
                _base_env(tmp, PYTHONPATH=str(tmp)),
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            note = (base / "src" / "x.c.md").read_text(encoding="utf-8")
            self.assertIn("provenance=non-tty", note)
            self.assertIn("source=agent", note)
            self.assertNotIn("provenance=interactive-tty", note)

    def test_wsl_consent_grant_still_refuses_piped_stdin(self):
        """The grant ceremony's fd gate must behave identically through
        the re-exec: piped stdin refuses before any consent logic."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            proc = _run(
                [sys.executable, str(LIBEXEC / "raptor-wsl-consent"),
                 "grant"],
                _base_env(tmp),
            )
            self.assertEqual(proc.returncode, 3, msg=proc.stdout)
            self.assertIn("interactive terminal", proc.stderr)


class GuardProbeTests(unittest.TestCase):
    """Direct behaviour of the shipped guard bytes, via a probe script
    that prints what the authority gates would read."""

    _PAYLOAD = (
        "\nimport json\n"
        "print(json.dumps({\n"
        "    'argv': sys.argv[1:],\n"
        "    'isolated': sys.flags.isolated,\n"
        "    'no_user_site': sys.flags.no_user_site,\n"
        "    'ttys': [sys.stdin.isatty(), sys.stdout.isatty(),\n"
        "             sys.stderr.isatty()],\n"
        "}))\n"
    )

    def _probe(self, tmp: Path, *, read_stdin: bool = False) -> Path:
        payload = self._PAYLOAD
        if read_stdin:
            payload = (
                "\nimport json\n"
                "print(json.dumps({'argv': sys.argv[1:],\n"
                "    'isolated': sys.flags.isolated,\n"
                "    'stdin': sys.stdin.read()}))\n"
            )
        probe = tmp / "probe.py"
        probe.write_text(_guard_block() + payload, encoding="utf-8")
        return probe

    def test_argv_and_stdin_survive_the_reexec(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            probe = self._probe(tmp, read_stdin=True)
            args = ["--flag", "a b", "π-値", "-x", "", "--", "trailing"]
            proc = _run(
                [sys.executable, str(probe), *args],
                _base_env(tmp),
                stdin="ceremony phrase\n",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(data["argv"], args)
            self.assertEqual(data["stdin"], "ceremony phrase\n")
            self.assertEqual(data["isolated"], 1)

    def test_already_isolated_interpreter_runs_straight_through(self):
        """Loop-freedom, both halves: -I invocation never re-execs
        (same output, no exec), and the re-exec route terminates (the
        previous test completed) — sys.flags.isolated is the guard's
        own terminator."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            probe = self._probe(tmp)
            via_reexec = _run(
                [sys.executable, str(probe), "x"], _base_env(tmp))
            direct = _run(
                [sys.executable, "-I", str(probe), "x"], _base_env(tmp))
            self.assertEqual(via_reexec.returncode, 0)
            self.assertEqual(direct.returncode, 0)
            self.assertEqual(
                json.loads(via_reexec.stdout),
                json.loads(direct.stdout),
            )
            # The re-execed interpreter forces user site OFF — the
            # zero-variable forge shape cannot exist in it.
            self.assertEqual(
                json.loads(via_reexec.stdout)["no_user_site"], 1)

    def test_import_does_not_reexec_the_importer(self):
        """__main__ gate: importing a module that carries the guard
        must never exec the importing process away."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            guardmod = tmp / "guardmod.py"
            guardmod.write_text(
                _guard_block() + "\nCARRIED = True\n", encoding="utf-8",
            )
            proc = _run(
                [sys.executable, "-c",
                 f"import sys; sys.path.insert(0, {str(tmp)!r}); "
                 "import guardmod; print('imported-ok', "
                 "guardmod.CARRIED, sys.flags.isolated)"],
                _base_env(tmp),
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("imported-ok True 0", proc.stdout)

    def test_all_three_tty_fds_survive_the_reexec(self):
        """The ceremony gates (fp --ceremony all-fds-TTY, wsl-consent
        grant) read isatty on the std fds — the re-exec must hand the
        isolated child the SAME terminal."""
        try:
            import pty
        except ImportError:  # pragma: no cover — POSIX-only CI
            self.skipTest("pty unavailable")
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            probe = self._probe(tmp)
            master, slave = pty.openpty()
            try:
                proc = subprocess.Popen(
                    [sys.executable, str(probe), "tty-run"],
                    stdin=slave, stdout=slave, stderr=slave,
                    env=_base_env(tmp), cwd=str(REPO),
                )
                proc.wait(timeout=120)
                os.close(slave)
                slave = -1
                chunks = []
                while True:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:  # EIO once the slave side closes
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
            finally:
                if slave != -1:
                    os.close(slave)
                os.close(master)
            out = b"".join(chunks).decode("utf-8", errors="replace")
            self.assertEqual(proc.returncode, 0, msg=out)
            data = json.loads(out.strip().splitlines()[-1])
            self.assertEqual(data["ttys"], [True, True, True])
            self.assertEqual(data["isolated"], 1)
            self.assertEqual(data["argv"], ["tty-run"])


if __name__ == "__main__":
    unittest.main()
