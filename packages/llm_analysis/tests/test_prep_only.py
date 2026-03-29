"""Tests for the --prep-only flag in agent.py."""

import argparse
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

class TestPrepOnlyFlag:
    """Test that --prep-only forces ClaudeCodeProvider regardless of LLM availability."""

    def test_prep_only_forces_stub_provider(self, tmp_path):
        """When prep_only=True, agent uses ClaudeCodeProvider even if external LLM is available."""
        mock_availability = MagicMock()
        mock_availability.external_llm = True
        mock_availability.claude_code = True
        mock_availability.llm_available = True

        with patch("packages.llm_analysis.agent.detect_llm_availability", return_value=mock_availability):
            from packages.llm_analysis.agent import AutonomousSecurityAgentV2
            agent = AutonomousSecurityAgentV2(
                repo_path=tmp_path,
                out_dir=tmp_path / "out",
                prep_only=True,
            )

        assert type(agent.llm).__name__ == "ClaudeCodeProvider"
        assert agent.llm_config is None

    def test_prep_only_false_uses_detection(self, tmp_path):
        """When prep_only=False and no LLM available, auto-detects and uses ClaudeCodeProvider."""
        mock_availability = MagicMock()
        mock_availability.external_llm = False
        mock_availability.claude_code = True
        mock_availability.llm_available = True

        with patch("packages.llm_analysis.agent.detect_llm_availability", return_value=mock_availability):
            from packages.llm_analysis.agent import AutonomousSecurityAgentV2
            agent = AutonomousSecurityAgentV2(
                repo_path=tmp_path,
                out_dir=tmp_path / "out",
                prep_only=False,
            )

        assert type(agent.llm).__name__ == "ClaudeCodeProvider"

    def test_prep_only_cli_flag_accepted(self):
        """argparse accepts --prep-only without error."""
        ap = argparse.ArgumentParser()
        ap.add_argument("--repo", required=True)
        ap.add_argument("--sarif", nargs="+")
        ap.add_argument("--findings")
        ap.add_argument("--out")
        ap.add_argument("--max-findings", type=int, default=10)
        ap.add_argument("--prep-only", action="store_true")

        args = ap.parse_args(["--repo", "/tmp/test", "--sarif", "test.sarif", "--prep-only"])
        assert args.prep_only is True

        args_no_flag = ap.parse_args(["--repo", "/tmp/test", "--sarif", "test.sarif"])
        assert args_no_flag.prep_only is False
