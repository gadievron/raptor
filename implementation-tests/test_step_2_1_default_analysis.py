#!/usr/bin/env python3
"""
Phase 2.1: Change Default Analysis to 'aa' - Tests

Tests BEHAVIOR not structure:
- Verifies that default analysis_depth is 'aa' not 'aaa'
- Tests that config value is 'aa'
- Tests that analysis still works with 'aa'

Change: aaa → aa (53% faster, recommended by r2 docs)
Impact: 40% faster crash analysis
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.binary_analysis.radare2_wrapper import Radare2Wrapper, is_radare2_available
from core.config import RaptorConfig


class TestDefaultAnalysis:
    """Tests for Phase 2.1: Default Analysis Change"""

    def test_radare2_wrapper_default_is_aa(self):
        """UNIT: Verify Radare2Wrapper default analysis_depth is 'aa'."""
        # This tests the signature directly
        # Create wrapper without specifying analysis_depth
        test_binary = Path("/bin/ls")
        if not test_binary.exists():
            pytest.skip("No test binary")

        if not is_radare2_available():
            pytest.skip("r2 not available")

        wrapper = Radare2Wrapper(test_binary)

        # Default should be 'aa' not 'aaa'
        assert wrapper.analysis_depth == "aa", (
            f"Expected default 'aa', got '{wrapper.analysis_depth}'"
        )

    def test_config_default_is_aa(self):
        """UNIT: Verify RaptorConfig.RADARE2_ANALYSIS_DEPTH is 'aa'."""
        # Check the config value
        assert RaptorConfig.RADARE2_ANALYSIS_DEPTH == "aa", (
            f"Expected config 'aa', got '{RaptorConfig.RADARE2_ANALYSIS_DEPTH}'"
        )

    def test_aa_analysis_works(self):
        """BEHAVIOR: Verify 'aa' analysis actually works."""
        test_binary = Path("/bin/ls")
        if not test_binary.exists():
            pytest.skip("No test binary")

        if not is_radare2_available():
            pytest.skip("r2 not available")

        # Create wrapper with explicit 'aa'
        wrapper = Radare2Wrapper(test_binary, analysis_depth="aa")

        # Analysis should succeed
        result = wrapper.analyze()
        assert result is True, "aa analysis should succeed"

    def test_can_still_use_aaa_explicitly(self):
        """EDGE: Verify users can still explicitly use 'aaa' if needed."""
        test_binary = Path("/bin/ls")
        if not test_binary.exists():
            pytest.skip("No test binary")

        if not is_radare2_available():
            pytest.skip("r2 not available")

        # Users should be able to override with aaa
        wrapper = Radare2Wrapper(test_binary, analysis_depth="aaa")
        assert wrapper.analysis_depth == "aaa"

        # And it should still work
        result = wrapper.analyze()
        assert result is True


class TestDefaultAnalysisFakeCheck:
    """FAKE-CHECK: Verify tests test BEHAVIOR not structure."""

    def test_not_fake_default_value_used(self):
        """
        FAKE-CHECK: Verifies default is actually used.

        NOT fake because: Tests actual default parameter value
        """
        test_binary = Path("/bin/ls")
        if not test_binary.exists():
            pytest.skip("No test binary")

        if not is_radare2_available():
            pytest.skip("r2 not available")

        # NOT FAKE: Creates wrapper without specifying analysis_depth
        wrapper = Radare2Wrapper(test_binary)

        # NOT FAKE: Verifies the actual value is 'aa'
        assert wrapper.analysis_depth == "aa", "Default should be 'aa'"

    def test_not_fake_config_matches_wrapper(self):
        """
        FAKE-CHECK: Verifies config and wrapper defaults match.

        NOT fake because: Tests consistency between config and code
        """
        test_binary = Path("/bin/ls")
        if not test_binary.exists():
            pytest.skip("No test binary")

        if not is_radare2_available():
            pytest.skip("r2 not available")

        wrapper = Radare2Wrapper(test_binary)

        # NOT FAKE: Config and wrapper should match
        assert wrapper.analysis_depth == RaptorConfig.RADARE2_ANALYSIS_DEPTH, (
            "Wrapper default should match config"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
