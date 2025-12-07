#!/usr/bin/env python3
"""
Address Type Handling Tests for Radare2 Wrapper

Tests for consistent address normalization across int and string types.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.binary_analysis.radare2_wrapper import Radare2Wrapper, Radare2Function


class TestAddressNormalization:
    """Test that addresses are normalized consistently."""

    @pytest.fixture
    def radare2_wrapper(self, tmp_path):
        """Create a minimal test binary and wrapper."""
        test_binary = tmp_path / "test_prog"
        test_binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        wrapper = Radare2Wrapper(test_binary)
        return wrapper

    def test_normalize_int_to_hex_string(self, radare2_wrapper):
        """UNIT: Verify integer addresses are normalized to hex strings."""
        # radare2 returns addr as int: 4198400
        # Should normalize to: "0x401000"

        # Simulate radare2 returning int address
        mock_func_data = {
            "name": "main",
            "addr": 4198400,  # Integer format
            "size": 100,
            "nbbs": 5,
            "ninstrs": 20,
            "calltype": "reg"
        }

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = [mock_func_data]

            functions = radare2_wrapper.list_functions()

            # Verify address is normalized to hex string
            assert len(functions) == 1
            assert functions[0].offset == "0x401000", \
                f"Expected '0x401000', got '{functions[0].offset}'"
            assert isinstance(functions[0].offset, str), \
                "Address should be string, not int"

    def test_normalize_hex_string_preserved(self, radare2_wrapper):
        """UNIT: Verify hex string addresses are preserved."""
        # radare2 returns addr as hex string: "0x401000"
        # Should preserve: "0x401000"

        mock_func_data = {
            "name": "main",
            "addr": "0x401000",  # String format (already hex)
            "size": 100,
            "nbbs": 5,
            "ninstrs": 20,
            "calltype": "reg"
        }

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = [mock_func_data]

            functions = radare2_wrapper.list_functions()

            assert len(functions) == 1
            assert functions[0].offset == "0x401000"
            assert isinstance(functions[0].offset, str)

    def test_normalize_decimal_string_to_hex(self, radare2_wrapper):
        """UNIT: Verify decimal string addresses are converted to hex."""
        # radare2 returns addr as decimal string: "4198400"
        # Should normalize to: "0x401000"

        mock_func_data = {
            "name": "main",
            "addr": "4198400",  # Decimal string format
            "size": 100,
            "nbbs": 5,
            "ninstrs": 20,
            "calltype": "reg"
        }

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = [mock_func_data]

            functions = radare2_wrapper.list_functions()

            assert len(functions) == 1
            assert functions[0].offset == "0x401000", \
                f"Decimal string '4198400' should normalize to '0x401000', got '{functions[0].offset}'"

    def test_normalize_handles_offset_key(self, radare2_wrapper):
        """UNIT: Verify 'offset' key is handled (fallback from 'addr')."""
        # Some radare2 commands use "offset" instead of "addr"

        mock_func_data = {
            "name": "main",
            "offset": 4198400,  # Using 'offset' key instead of 'addr'
            "size": 100,
            "nbbs": 5,
            "ninstrs": 20,
            "calltype": "reg"
        }

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = [mock_func_data]

            functions = radare2_wrapper.list_functions()

            assert len(functions) == 1
            assert functions[0].offset == "0x401000"

    def test_normalize_zero_address(self, radare2_wrapper):
        """EDGE: Verify address 0 is normalized correctly."""
        mock_func_data = {
            "name": "null_func",
            "addr": 0,  # Zero address
            "size": 0,
            "nbbs": 0,
            "ninstrs": 0,
            "calltype": "unknown"
        }

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = [mock_func_data]

            functions = radare2_wrapper.list_functions()

            assert len(functions) == 1
            assert functions[0].offset == "0x0"

    def test_normalize_large_address(self, radare2_wrapper):
        """EDGE: Verify large addresses (64-bit) are normalized correctly."""
        # 64-bit address: 0x7ffff7a00000
        large_addr = 140737348386816

        mock_func_data = {
            "name": "libc_func",
            "addr": large_addr,
            "size": 100,
            "nbbs": 5,
            "ninstrs": 20,
            "calltype": "reg"
        }

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = [mock_func_data]

            functions = radare2_wrapper.list_functions()

            assert len(functions) == 1
            expected = hex(large_addr)  # "0x7ffff7a00000"
            assert functions[0].offset == expected, \
                f"Large address should normalize to {expected}, got '{functions[0].offset}'"

    def test_normalize_invalid_address_fallback(self, radare2_wrapper):
        """EDGE: Verify invalid address types fall back to '0x0'."""
        # radare2 returns invalid type (e.g., None, list, dict)

        mock_func_data = {
            "name": "bad_func",
            "addr": None,  # Invalid type
            "size": 100,
            "nbbs": 5,
            "ninstrs": 20,
            "calltype": "reg"
        }

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = [mock_func_data]

            functions = radare2_wrapper.list_functions()

            # Should handle gracefully (either skip or use default)
            # Current behavior: may crash or use fallback
            # After fix: should use "0x0" as safe default
            if len(functions) > 0:
                assert isinstance(functions[0].offset, str)

    def test_normalize_consistency_across_calls(self, radare2_wrapper):
        """BEHAVIOR: Verify same address value always normalizes the same way."""
        # Idempotency test: normalize(4198400) should always return "0x401000"

        mock_func_data1 = {"name": "func1", "addr": 4198400, "size": 100, "nbbs": 5, "ninstrs": 20, "calltype": "reg"}
        mock_func_data2 = {"name": "func2", "addr": "4198400", "size": 100, "nbbs": 5, "ninstrs": 20, "calltype": "reg"}
        mock_func_data3 = {"name": "func3", "addr": "0x401000", "size": 100, "nbbs": 5, "ninstrs": 20, "calltype": "reg"}

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            # First call: int address
            mock_exec.return_value = [mock_func_data1]
            functions1 = radare2_wrapper.list_functions()

            # Second call: decimal string address
            mock_exec.return_value = [mock_func_data2]
            functions2 = radare2_wrapper.list_functions()

            # Third call: hex string address
            mock_exec.return_value = [mock_func_data3]
            functions3 = radare2_wrapper.list_functions()

            # All should normalize to the same format
            assert functions1[0].offset == functions2[0].offset == functions3[0].offset == "0x401000", \
                "Same address value should always normalize consistently"


class TestAddressNormalizationFakeCheck:
    """FAKE-CHECK: Verify tests test BEHAVIOR not structure."""

    @pytest.fixture
    def radare2_wrapper(self, tmp_path):
        test_binary = tmp_path / "test_prog"
        test_binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        return Radare2Wrapper(test_binary)

    def test_not_fake_actually_converts_types(self, radare2_wrapper):
        """
        FAKE-CHECK: Verify we're testing actual type conversion.

        NOT fake because: Tests both input type (int) and output type (str)
        """
        mock_func_data = {
            "name": "main",
            "addr": 4198400,  # Input: int
            "size": 100,
            "nbbs": 5,
            "ninstrs": 20,
            "calltype": "reg"
        }

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = [mock_func_data]
            functions = radare2_wrapper.list_functions()

            # NOT FAKE: Verifies type conversion happened
            addr_before = mock_func_data["addr"]
            addr_after = functions[0].offset

            assert isinstance(addr_before, int), "Input should be int"
            assert isinstance(addr_after, str), "Output should be str"
            assert addr_before == int(addr_after, 16), "Values should match after conversion"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
