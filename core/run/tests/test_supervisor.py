"""Supervisor detection + self-bound derivation (core.run.supervisor)."""

import unittest
from unittest import mock

from core.run import supervisor
from core.run.supervisor import (
    DEFAULT_SUBAGENT_CAP_S,
    DRAIN_MARGIN_S,
    MIN_BOUND_S,
    is_subagent_shell,
    subagent_shell_cap_s,
    supervisor_wall_bound,
)


def _env(**vars):  # test shorthand
    """Patch os.environ to exactly *vars* for the supervisor module."""
    return mock.patch.dict("os.environ", vars, clear=True)


class TestSubagentDetection(unittest.TestCase):

    def test_subagent_via_ai_agent_suffix(self):
        with _env(CLAUDECODE="1", AI_AGENT="claude-code_2-1-232_agent"):
            self.assertTrue(is_subagent_shell())

    def test_subagent_via_child_session(self):
        with _env(CLAUDECODE="1", CLAUDE_CODE_CHILD_SESSION="1"):
            self.assertTrue(is_subagent_shell())

    def test_main_thread_shell_not_subagent(self):
        with _env(CLAUDECODE="1", AI_AGENT="claude-code_2-1-232"):
            self.assertFalse(is_subagent_shell())

    def test_outside_claude_never_subagent(self):
        # No CLAUDECODE and no claude ancestor: even subagent-shaped
        # stamps (copied env, CI) must not trigger.
        with _env(AI_AGENT="claude-code_2-1-232_agent"), \
                mock.patch.object(
                    supervisor, "_under_claude_session",
                    return_value=False):
            self.assertFalse(is_subagent_shell())

    def test_claude_ancestor_counts_without_claudecode_env(self):
        with _env(CLAUDE_CODE_CHILD_SESSION="1"), \
                mock.patch(
                    "core.run.metadata._find_claude_ancestor",
                    return_value=12345):
            self.assertTrue(is_subagent_shell())


class TestCapAndBound(unittest.TestCase):

    def test_default_cap_and_documented_3300s_bound(self):
        with _env(CLAUDECODE="1", CLAUDE_CODE_CHILD_SESSION="1"):
            self.assertEqual(subagent_shell_cap_s(), DEFAULT_SUBAGENT_CAP_S)
            bound = supervisor_wall_bound()
            self.assertIsNotNone(bound)
            self.assertEqual(bound.cap_s, 3600.0)
            self.assertEqual(bound.bound_s, 3300.0)
            self.assertEqual(
                bound.bound_s, DEFAULT_SUBAGENT_CAP_S - DRAIN_MARGIN_S,
            )

    def test_env_cap_override(self):
        with _env(CLAUDECODE="1", CLAUDE_CODE_CHILD_SESSION="1",
                  CLAUDE_SUBAGENT_BG_SHELL_MAX_MS="7200000"):
            bound = supervisor_wall_bound()
            self.assertEqual(bound.cap_s, 7200.0)
            self.assertEqual(bound.bound_s, 7200.0 - DRAIN_MARGIN_S)

    def test_tiny_cap_floors_at_min_bound(self):
        with _env(CLAUDECODE="1", CLAUDE_CODE_CHILD_SESSION="1",
                  CLAUDE_SUBAGENT_BG_SHELL_MAX_MS="120000"):
            bound = supervisor_wall_bound()
            self.assertEqual(bound.bound_s, MIN_BOUND_S)

    def test_garbage_cap_falls_back_to_default(self):
        for raw in ("soon", "", "-5000", "0"):
            with _env(CLAUDECODE="1", CLAUDE_CODE_CHILD_SESSION="1",
                      CLAUDE_SUBAGENT_BG_SHELL_MAX_MS=raw):
                self.assertEqual(
                    subagent_shell_cap_s(), DEFAULT_SUBAGENT_CAP_S,
                    f"raw={raw!r}",
                )

    def test_main_thread_gets_no_bound(self):
        with _env(CLAUDECODE="1"):
            self.assertIsNone(supervisor_wall_bound())


class TestCliFlagSurface(unittest.TestCase):

    def test_run_and_resume_expose_opt_out(self):
        import subprocess
        import sys
        from pathlib import Path

        raptor_dir = Path(supervisor.__file__).resolve().parents[2]
        import os
        env = dict(os.environ, CLAUDECODE="1",
                   PYTHONPATH=str(raptor_dir))
        for sub in ("run", "resume"):
            r = subprocess.run(
                [sys.executable,
                 str(raptor_dir / "libexec" / "raptor-audit"),
                 sub, "--help"],
                env=env, capture_output=True, text=True, timeout=120,
                check=False,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("--no-supervisor-bound", r.stdout)


if __name__ == "__main__":
    unittest.main()
