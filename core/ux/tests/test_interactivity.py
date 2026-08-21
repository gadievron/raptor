"""Hermetic tests for the session interactivity gate.

Every production input is injectable (``environ``, ``ci``,
``std_fd_interactive``, ``human_probe``), so no test here depends on
the invoking terminal, the CI environment, or the process ancestry.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path

from core.ux.interactivity import (
    INTERACTIVE,
    NON_INTERACTIVE,
    NONINTERACTIVE_ENV,
    session_interactivity,
    session_may_ask,
)

REPO = Path(__file__).resolve().parents[3]
SHIM = REPO / "libexec" / "raptor-may-ask"


def _gate(env, *, ci=lambda: False, std=False, probe=lambda: False):
    return session_may_ask(
        env, ci=ci, std_fd_interactive=std, human_probe=probe,
    )


class OverrideTests(unittest.TestCase):
    def test_noninteractive_env_wins_over_everything(self):
        env = {NONINTERACTIVE_ENV: "1"}
        self.assertFalse(_gate(env, std=True, probe=lambda: True))

    def test_noninteractive_env_falsey_values_ignored(self):
        for value in ("", "0", "false", "no", "off", " FALSE "):
            env = {NONINTERACTIVE_ENV: value}
            self.assertTrue(
                _gate(env, std=True), msg=f"value={value!r}",
            )

    def test_ci_forces_non_interactive(self):
        """CI dominates even a pseudo-TTY (rule-of-two hardening)."""
        self.assertFalse(
            _gate({}, ci=lambda: True, std=True, probe=lambda: True),
        )

    def test_live_ci_default_is_rule_of_two(self):
        """Without an injected ``ci``, the gate consults
        rule_of_two.is_ci — RAPTOR_CI (its authoritative marker) must
        force the verdict shut."""
        old = os.environ.get("RAPTOR_CI")
        os.environ["RAPTOR_CI"] = "1"
        try:
            self.assertFalse(
                session_may_ask(
                    {}, std_fd_interactive=True, human_probe=lambda: True,
                ),
            )
        finally:
            if old is None:
                os.environ.pop("RAPTOR_CI", None)
            else:
                os.environ["RAPTOR_CI"] = old


class SignalTests(unittest.TestCase):
    def test_std_fd_tty_is_interactive(self):
        self.assertTrue(_gate({}, std=True, probe=lambda: False))

    def test_human_terminal_probe_is_interactive(self):
        self.assertTrue(_gate({}, std=False, probe=lambda: True))

    def test_no_signal_fails_closed(self):
        self.assertFalse(_gate({}, std=False, probe=lambda: False))

    def test_probe_error_fails_closed(self):
        def broken():
            raise OSError("no /proc")
        self.assertFalse(_gate({}, std=False, probe=broken))

    def test_string_verdicts(self):
        kwargs = {"ci": lambda: False, "human_probe": lambda: False}
        self.assertEqual(
            session_interactivity({}, std_fd_interactive=True, **kwargs),
            INTERACTIVE,
        )
        self.assertEqual(
            session_interactivity({}, std_fd_interactive=False, **kwargs),
            NON_INTERACTIVE,
        )


class ShimTests(unittest.TestCase):
    """The libexec shim, run hermetically (no TTY on any fd)."""

    def _run(self, extra_env):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
        }
        env.update(extra_env)
        return subprocess.run(
            [sys.executable, str(SHIM)],
            capture_output=True, text=True, timeout=60, env=env,
            stdin=subprocess.DEVNULL,
        )

    def test_refuses_without_trust_marker(self):
        proc = self._run({})
        self.assertEqual(proc.returncode, 2)
        self.assertIn("internal dispatch script", proc.stderr)

    def test_explicit_noninteractive_marker(self):
        proc = self._run({
            "_RAPTOR_TRUSTED": "1", NONINTERACTIVE_ENV: "1",
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), NON_INTERACTIVE)

    def test_ci_marker_yields_non_interactive(self):
        proc = self._run({"_RAPTOR_TRUSTED": "1", "RAPTOR_CI": "1"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), NON_INTERACTIVE)


if __name__ == "__main__":
    unittest.main()
