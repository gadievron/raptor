#!/usr/bin/env python3
"""
Phase 2.4: Security Helper Method - Tests

Tests BEHAVIOR:
- Verifies get_security_info() returns security mitigation data
- Tests that it works without requiring analysis
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.binary_analysis.radare2_wrapper import Radare2Wrapper, is_radare2_available


class TestSecurityHelper:
    """Tests for Phase 2.4: Security Helper Method"""

    def test_get_security_info_returns_dict(self):
        """UNIT: Verify get_security_info() returns a dict."""
        if not is_radare2_available():
            pytest.skip("r2 not available")

        binary = Path("/bin/ls")
        if not binary.exists():
            pytest.skip("No test binary")

        wrapper = Radare2Wrapper(binary)
        security_info = wrapper.get_security_info()

        assert isinstance(security_info, dict)

    def test_get_security_info_has_expected_keys(self):
        """UNIT: Verify security info has expected security flags."""
        if not is_radare2_available():
            pytest.skip("r2 not available")

        binary = Path("/bin/ls")
        if not binary.exists():
            pytest.skip("No test binary")

        wrapper = Radare2Wrapper(binary)
        security_info = wrapper.get_security_info()

        # Should have standard security mitigation keys
        expected_keys = ['canary', 'nx', 'pie', 'relocs', 'stripped', 'static', 'crypto']
        for key in expected_keys:
            assert key in security_info, f"Missing key: {key}"

    def test_get_security_info_works_without_analysis(self):
        """BEHAVIOR: Verify security info works without analysis."""
        if not is_radare2_available():
            pytest.skip("r2 not available")

        binary = Path("/bin/ls")
        if not binary.exists():
            pytest.skip("No test binary")

        wrapper = Radare2Wrapper(binary)
        # Don't run analyze()
        security_info = wrapper.get_security_info()

        # Should still return valid data
        assert isinstance(security_info, dict)
        assert len(security_info) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
