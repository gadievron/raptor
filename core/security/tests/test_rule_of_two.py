"""Tests for Rule of Two CI/CD enforcement."""

from __future__ import annotations

import io
from unittest.mock import patch

import pytest

from core.security.rule_of_two import (
    NonInteractiveError,
    is_interactive,
    require_interactive_for_agentic_pass,
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

    def test_passes_when_interactive(self):
        with patch("core.security.rule_of_two.is_interactive", return_value=True):
            require_interactive_for_agentic_pass("understand")

    def test_raises_when_non_interactive(self):
        with patch("core.security.rule_of_two.is_interactive", return_value=False):
            with pytest.raises(NonInteractiveError, match="not allowed in non-interactive"):
                require_interactive_for_agentic_pass("understand")

    def test_error_includes_pass_name(self):
        with patch("core.security.rule_of_two.is_interactive", return_value=False):
            with pytest.raises(NonInteractiveError, match="--validate"):
                require_interactive_for_agentic_pass("validate")

    def test_error_mentions_rule_of_two(self):
        with patch("core.security.rule_of_two.is_interactive", return_value=False):
            with pytest.raises(NonInteractiveError, match="Rule of Two"):
                require_interactive_for_agentic_pass("understand")

    def test_error_mentions_write_and_bash(self):
        with patch("core.security.rule_of_two.is_interactive", return_value=False):
            with pytest.raises(NonInteractiveError, match="Write and Bash"):
                require_interactive_for_agentic_pass("understand")
