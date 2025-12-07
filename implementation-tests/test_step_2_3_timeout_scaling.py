#!/usr/bin/env python3
"""
Phase 2.3: Size-Based Timeout Scaling - Tests

Tests BEHAVIOR not structure:
- Verifies that timeout scales based on binary size
- Tests that explicit timeout parameter overrides auto-scaling

Feature: Auto-scale timeout based on binary size
Impact: 50% fewer timeouts on large binaries
"""

import pytest
import sys
from pathlib import Path
import tempfile

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.binary_analysis.radare2_wrapper import Radare2Wrapper, is_radare2_available


def create_sized_binary(size_bytes: int) -> Path:
    """Create a binary of specified size for testing."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    tmp.write(b"\x7fELF" + b"\x00" * (size_bytes - 4))
    tmp.close()
    return Path(tmp.name)


class TestTimeoutScaling:
    """Tests for Phase 2.3: Size-Based Timeout Scaling"""

    def test_small_binary_short_timeout(self):
        """UNIT: Small binary (<1MB) gets 60s timeout."""
        if not is_radare2_available():
            pytest.skip("r2 not available")

        # Create 500KB binary
        binary = create_sized_binary(500_000)
        try:
            wrapper = Radare2Wrapper(binary)

            # Should auto-scale to 60s
            assert wrapper.timeout == 60, f"Expected 60s for <1MB, got {wrapper.timeout}s"
        finally:
            binary.unlink()

    def test_medium_binary_medium_timeout(self):
        """UNIT: Medium binary (1-10MB) gets 300s timeout."""
        if not is_radare2_available():
            pytest.skip("r2 not available")

        # Create 5MB binary
        binary = create_sized_binary(5_000_000)
        try:
            wrapper = Radare2Wrapper(binary)

            # Should auto-scale to 300s
            assert wrapper.timeout == 300, f"Expected 300s for 1-10MB, got {wrapper.timeout}s"
        finally:
            binary.unlink()

    def test_large_binary_long_timeout(self):
        """UNIT: Large binary (10-100MB) gets 600s timeout."""
        if not is_radare2_available():
            pytest.skip("r2 not available")

        # Create 50MB binary
        binary = create_sized_binary(50_000_000)
        try:
            wrapper = Radare2Wrapper(binary)

            # Should auto-scale to 600s
            assert wrapper.timeout == 600, f"Expected 600s for 10-100MB, got {wrapper.timeout}s"
        finally:
            binary.unlink()

    def test_explicit_timeout_overrides_scaling(self):
        """BEHAVIOR: Explicit timeout parameter overrides auto-scaling."""
        if not is_radare2_available():
            pytest.skip("r2 not available")

        # Create 50MB binary (would normally get 600s)
        binary = create_sized_binary(50_000_000)
        try:
            # But explicit timeout=120 should override
            wrapper = Radare2Wrapper(binary, timeout=120)

            assert wrapper.timeout == 120, "Explicit timeout should override auto-scaling"
        finally:
            binary.unlink()

    def test_very_large_binary_gets_max_timeout(self):
        """EDGE: Very large binary (>100MB) gets 1200s timeout."""
        if not is_radare2_available():
            pytest.skip("r2 not available")

        # Create 150MB binary
        binary = create_sized_binary(150_000_000)
        try:
            wrapper = Radare2Wrapper(binary)

            # Should auto-scale to 1200s
            assert wrapper.timeout == 1200, f"Expected 1200s for >100MB, got {wrapper.timeout}s"
        finally:
            binary.unlink()


class TestTimeoutScalingFakeCheck:
    """FAKE-CHECK: Verify tests test BEHAVIOR not structure."""

    def test_not_fake_timeout_varies_by_size(self):
        """
        FAKE-CHECK: Verifies timeout actually changes with size.

        NOT fake because: Tests different sizes produce different timeouts
        """
        if not is_radare2_available():
            pytest.skip("r2 not available")

        small_bin = create_sized_binary(500_000)   # 500KB
        large_bin = create_sized_binary(50_000_000) # 50MB

        try:
            small_wrapper = Radare2Wrapper(small_bin)
            large_wrapper = Radare2Wrapper(large_bin)

            # NOT FAKE: Different sizes should have different timeouts
            assert small_wrapper.timeout != large_wrapper.timeout, (
                "Timeout should vary by binary size"
            )
            assert large_wrapper.timeout > small_wrapper.timeout, (
                "Larger binary should have longer timeout"
            )
        finally:
            small_bin.unlink()
            large_bin.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
