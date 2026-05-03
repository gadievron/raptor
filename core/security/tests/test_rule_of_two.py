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
