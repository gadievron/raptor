#!/usr/bin/env python3
"""
Phase 2.5: Analysis-Free Mode - Tests

Tests BEHAVIOR:
- Verifies analysis can be skipped for fast triage
- Tests that empty analysis_depth works
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.binary_analysis.radare2_wrapper import Radare2Wrapper, is_radare2_available


class TestAnalysisFreeMode:
    """Tests for Phase 2.5: Analysis-Free Mode"""

    def test_empty_analysis_depth_skips_analysis(self):
        """UNIT: Empty analysis_depth skips analysis."""
        if not is_radare2_available():
            pytest.skip("r2 not available")

        binary = Path("/bin/ls")
        if not binary.exists():
            pytest.skip("No test binary")

        # Create wrapper with empty analysis_depth
        wrapper = Radare2Wrapper(binary, analysis_depth="")

        # analyze() should return True (success) but skip actual analysis
        result = wrapper.analyze()
        assert result is True

    def test_can_use_commands_without_analysis(self):
        """BEHAVIOR: Can use basic commands without analysis."""
        if not is_radare2_available():
            pytest.skip("r2 not available")

        binary = Path("/bin/ls")
        if not binary.exists():
            pytest.skip("No test binary")

        wrapper = Radare2Wrapper(binary, analysis_depth="")

        # Should be able to get binary info without analysis
        info = wrapper.get_binary_info()
        assert isinstance(info, (dict, list)), "Should return data"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
