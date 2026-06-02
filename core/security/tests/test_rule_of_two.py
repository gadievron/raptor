"""Tests for Rule of Two CI/CD enforcement."""

from __future__ import annotations

import io
from unittest.mock import patch

import pytest

import core.security.rule_of_two as r2
from core.security.rule_of_two import (
    NonInteractiveError,
    is_interactive,
    require_human_or_sandbox_for_agentic_pass,
    require_interactive_for_weakened_defenses,
)


class TestIsInteractive:

    @pytest.fixture(autouse=True)
    def _no_ci_env(self, monkeypatch):
        # `is_interactive()` requires BOTH a TTY AND no CI env var.
        # These TTY-only tests need to clear any CI flag the test
        # runner itself sets — GitHub Actions sets CI=true /
        # GITHUB_ACTIONS=true, which would override the mocked TTY
        # and make `is_interactive()` return False on CI even though
        # the test mocks stdin as a TTY. Clear the curated CI list
        # so each test isolates the TTY codepath cleanly.
        from core.security.rule_of_two import _CI_ENV_VARS
        for name in _CI_ENV_VARS:
            monkeypatch.delenv(name, raising=False)

    def test_true_when_tty(self):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            assert is_interactive() is True

    def test_false_when_not_tty(self):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            assert is_interactive() is False

    def test_false_when_no_isatty(self):
        with patch("sys.stdin", new=io.StringIO()):
            assert is_interactive() is False

    def test_false_when_tty_but_ci_env_set(self, monkeypatch):
        # CI runners that allocate a pseudo-TTY (docker -t, GHA
        # tty: true, Jenkins ssh agent) used to slip past the
        # rule-of-two gate. The CI-env probe added in batch 076
        # closes that gap.
        monkeypatch.setenv("CI", "true")
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            assert is_interactive() is False


class TestWeakenedDefensesGate:

    def test_passes_when_interactive(self):
        with patch("core.security.rule_of_two.is_interactive", return_value=True):
            require_interactive_for_weakened_defenses()

    def test_raises_when_non_interactive(self):
        with patch("core.security.rule_of_two.is_interactive", return_value=False):
            with pytest.raises(NonInteractiveError, match="not allowed in non-interactive"):
                require_interactive_for_weakened_defenses()

    def test_error_message_mentions_flag(self):
        with patch("core.security.rule_of_two.is_interactive", return_value=False):
            with pytest.raises(NonInteractiveError, match="accept-weakened-defenses"):
                require_interactive_for_weakened_defenses()


class TestAgenticPassGate:
    """Either/or gate: allow when a human terminal OR an effective sandbox is
    present; block only the non-interactive + no-sandbox quadrant.

    The two legs are mocked at their helper boundary so these tests don't
    depend on the real process tree / sandbox capability of the test host.
    """

    @staticmethod
    def _patch(*, human: bool, sandbox: bool):
        return (
            patch("core.security.rule_of_two._session_has_human_terminal",
                  return_value=human),
            patch("core.security.rule_of_two._sandbox_will_contain",
                  return_value=sandbox),
        )

    def _run(self, *, human: bool, sandbox: bool, pass_name: str = "understand"):
        p1, p2 = self._patch(human=human, sandbox=sandbox)
        with p1, p2:
            require_human_or_sandbox_for_agentic_pass(pass_name)

    # --- the 2x2 matrix: only (no human, no sandbox) blocks ---

    def test_human_and_sandbox_allows(self):
        self._run(human=True, sandbox=True)  # no raise

    def test_human_no_sandbox_allows(self):
        # Interactive operator who disabled the sandbox — they own the risk.
        self._run(human=True, sandbox=False)

    def test_sandbox_no_human_allows(self):
        # CI/cron with containment — the common automated case.
        self._run(human=False, sandbox=True)

    def test_neither_blocks(self):
        with pytest.raises(NonInteractiveError):
            self._run(human=False, sandbox=False)

    # --- error message content (block quadrant) ---

    def test_error_includes_pass_name(self):
        with pytest.raises(NonInteractiveError, match="--validate"):
            self._run(human=False, sandbox=False, pass_name="validate")

    def test_error_mentions_rule_of_two(self):
        with pytest.raises(NonInteractiveError, match="Rule of Two"):
            self._run(human=False, sandbox=False)

    def test_error_mentions_write_and_bash(self):
        with pytest.raises(NonInteractiveError, match="Write and Bash"):
            self._run(human=False, sandbox=False)

    def test_error_mentions_both_remedies(self):
        # The message must point at both escape hatches: enable sandbox OR
        # run interactively. Otherwise an operator only learns half the fix.
        with pytest.raises(NonInteractiveError, match="sandbox"):
            self._run(human=False, sandbox=False)
        with pytest.raises(NonInteractiveError, match="interactive session"):
            self._run(human=False, sandbox=False)


class TestSessionHumanTerminal:

    @pytest.fixture(autouse=True)
    def _no_ci_env(self, monkeypatch):
        for name in r2._CI_ENV_VARS:
            monkeypatch.delenv(name, raising=False)

    def test_true_when_terminal_ancestor(self, monkeypatch):
        monkeypatch.setattr(r2.sys, "platform", "linux")
        monkeypatch.setattr(r2, "_has_terminal_ancestor", lambda: True)
        assert r2._session_has_human_terminal() is True

    def test_false_in_ci_even_with_terminal(self, monkeypatch):
        # A CI runner with a pseudo-TTY ancestor must not count as
        # human-attended — same hole is_interactive() closes.
        monkeypatch.setenv("CI", "true")
        monkeypatch.setattr(r2, "_has_terminal_ancestor", lambda: True)
        assert r2._session_has_human_terminal() is False

    def test_falls_back_to_stdin_tty_when_no_ancestor(self, monkeypatch):
        monkeypatch.setattr(r2.sys, "platform", "linux")
        monkeypatch.setattr(r2, "_has_terminal_ancestor", lambda: False)
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            assert r2._session_has_human_terminal() is True

    def test_fail_closed_on_error(self, monkeypatch):
        def boom():
            raise RuntimeError("proc walk exploded")
        monkeypatch.setattr(r2.sys, "platform", "linux")
        monkeypatch.setattr(r2, "_has_terminal_ancestor", boom)
        # stdin.isatty also raises → overall fail-closed to False.
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.side_effect = RuntimeError("nope")
            assert r2._session_has_human_terminal() is False


class TestSandboxWillContain:

    def test_false_when_cli_disabled(self, monkeypatch):
        from core.sandbox import state
        monkeypatch.setattr(state, "_cli_sandbox_disabled", True, raising=False)
        assert r2._sandbox_will_contain() is False

    def test_false_when_profile_none(self, monkeypatch):
        from core.sandbox import state
        monkeypatch.setattr(state, "_cli_sandbox_disabled", False, raising=False)
        monkeypatch.setattr(state, "_cli_sandbox_profile", "none", raising=False)
        assert r2._sandbox_will_contain() is False

    def test_true_when_enabled_and_capable(self, monkeypatch):
        from core.sandbox import state
        monkeypatch.setattr(state, "_cli_sandbox_disabled", False, raising=False)
        monkeypatch.setattr(state, "_cli_sandbox_profile", None, raising=False)
        monkeypatch.setattr(r2.sys, "platform", "linux")
        monkeypatch.setattr(
            "core.sandbox.context.check_landlock_available", lambda: True
        )
        assert r2._sandbox_will_contain() is True

    def test_false_when_platform_cannot_enforce(self, monkeypatch):
        from core.sandbox import state
        monkeypatch.setattr(state, "_cli_sandbox_disabled", False, raising=False)
        monkeypatch.setattr(state, "_cli_sandbox_profile", None, raising=False)
        monkeypatch.setattr(r2.sys, "platform", "linux")
        monkeypatch.setattr(
            "core.sandbox.context.check_landlock_available", lambda: False
        )
        assert r2._sandbox_will_contain() is False

    def test_false_when_network_only_profile(self, monkeypatch):
        # network-only has use_landlock=False — egress is restricted but the
        # filesystem is open, so the untrusted sub-agent isn't write-confined.
        # Must NOT count as contained even though Landlock is available.
        from core.sandbox import state
        monkeypatch.setattr(state, "_cli_sandbox_disabled", False, raising=False)
        monkeypatch.setattr(state, "_cli_sandbox_profile", "network-only",
                            raising=False)
        monkeypatch.setattr(r2.sys, "platform", "linux")
        monkeypatch.setattr(
            "core.sandbox.context.check_landlock_available", lambda: True
        )
        assert r2._sandbox_will_contain() is False

    def test_true_for_debug_profile_when_capable(self, monkeypatch):
        # debug relaxes seccomp (ptrace) but keeps use_landlock=True, so
        # filesystem writes are still confined → contained.
        from core.sandbox import state
        monkeypatch.setattr(state, "_cli_sandbox_disabled", False, raising=False)
        monkeypatch.setattr(state, "_cli_sandbox_profile", "debug", raising=False)
        monkeypatch.setattr(r2.sys, "platform", "linux")
        monkeypatch.setattr(
            "core.sandbox.context.check_landlock_available", lambda: True
        )
        assert r2._sandbox_will_contain() is True
