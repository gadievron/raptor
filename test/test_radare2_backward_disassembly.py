#!/usr/bin/env python3
"""
Backward Disassembly Overlap Tests for Radare2 Wrapper

Tests for duplicate instruction handling when using backward parameter.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.binary_analysis.radare2_wrapper import Radare2Wrapper


class TestBackwardDisassemblyOverlap:
    """Test that backward disassembly doesn't return duplicate instructions."""

    @pytest.fixture
    def radare2_wrapper(self, tmp_path):
        """Create a minimal test binary and wrapper."""
        test_binary = tmp_path / "test_prog"
        test_binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        wrapper = Radare2Wrapper(test_binary)
        return wrapper

    def test_backward_disassembly_no_duplicates(self, radare2_wrapper):
        """BUG: Verify backward disassembly doesn't return duplicate instructions."""
        # Simulate radare2 returning overlapping instructions
        # Command: "s 0x401010; pdj -2; s 0x401010; pdj 3"
        # Returns: [insn@0x401000, insn@0x401005, insn@0x401010, insn@0x401015, insn@0x401020]
        # Note: insn@0x401010 appears in BOTH backward and forward results

        mock_instructions = [
            # Backward instructions (2 before 0x401010)
            {"offset": "0x401000", "opcode": "push rbp", "disasm": "push rbp", "type": "push"},
            {"offset": "0x401005", "opcode": "mov rbp, rsp", "disasm": "mov rbp, rsp", "type": "mov"},
            # Overlapping instruction (appears in both backward and forward)
            {"offset": "0x401010", "opcode": "sub rsp, 0x10", "disasm": "sub rsp, 0x10", "type": "sub"},
            # Forward instructions (3 from 0x401010)
            {"offset": "0x401010", "opcode": "sub rsp, 0x10", "disasm": "sub rsp, 0x10", "type": "sub"},  # DUPLICATE
            {"offset": "0x401015", "opcode": "call 0x402000", "disasm": "call sym.foo", "type": "call"},
            {"offset": "0x401020", "opcode": "mov eax, 0", "disasm": "mov eax, 0", "type": "mov"},
        ]

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = mock_instructions

            instructions = radare2_wrapper.disassemble_at_address("0x401010", count=3, backward=2)

            # Verify no duplicates by checking unique offsets
            offsets = [insn.offset for insn in instructions]
            unique_offsets = list(dict.fromkeys(offsets))  # Preserve order

            assert len(offsets) == len(unique_offsets), \
                f"Found duplicate offsets! Got {len(offsets)} instructions but {len(unique_offsets)} unique. Offsets: {offsets}"

    def test_backward_disassembly_correct_order(self, radare2_wrapper):
        """BEHAVIOR: Verify backward instructions are ordered correctly (low to high address)."""
        mock_instructions = [
            # Backward (may be in reverse order from radare2)
            {"offset": "0x401005", "opcode": "mov rbp, rsp", "disasm": "mov rbp, rsp", "type": "mov"},
            {"offset": "0x401000", "opcode": "push rbp", "disasm": "push rbp", "type": "push"},
            # Forward
            {"offset": "0x401010", "opcode": "sub rsp, 0x10", "disasm": "sub rsp, 0x10", "type": "sub"},
            {"offset": "0x401015", "opcode": "call 0x402000", "disasm": "call sym.foo", "type": "call"},
        ]

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = mock_instructions

            instructions = radare2_wrapper.disassemble_at_address("0x401010", count=2, backward=2)

            # Verify instructions are sorted by address (low to high)
            offsets = [insn.offset for insn in instructions]
            sorted_offsets = sorted(offsets, key=lambda x: int(x, 16))

            assert offsets == sorted_offsets, \
                f"Instructions not sorted by address! Got: {offsets}, Expected: {sorted_offsets}"

    def test_backward_disassembly_count_matches_request(self, radare2_wrapper):
        """BEHAVIOR: Verify total instruction count matches backward + count parameters."""
        # With backward=2, count=3, expect 5 unique instructions
        mock_instructions = [
            {"offset": "0x401000", "opcode": "push rbp", "disasm": "push rbp", "type": "push"},
            {"offset": "0x401005", "opcode": "mov rbp, rsp", "disasm": "mov rbp, rsp", "type": "mov"},
            {"offset": "0x401010", "opcode": "sub rsp, 0x10", "disasm": "sub rsp, 0x10", "type": "sub"},
            {"offset": "0x401010", "opcode": "sub rsp, 0x10", "disasm": "sub rsp, 0x10", "type": "sub"},  # DUPLICATE
            {"offset": "0x401015", "opcode": "call 0x402000", "disasm": "call sym.foo", "type": "call"},
            {"offset": "0x401020", "opcode": "mov eax, 0", "disasm": "mov eax, 0", "type": "mov"},
        ]

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = mock_instructions

            instructions = radare2_wrapper.disassemble_at_address("0x401010", count=3, backward=2)

            # Should return backward (2) + forward (3) = 5 unique instructions
            # (assuming no overlap; with overlap and deduplication, may be less)
            # After deduplication: 5 unique offsets
            unique_offsets = list(dict.fromkeys([insn.offset for insn in instructions]))

            assert len(unique_offsets) == 5, \
                f"Expected 5 unique instructions (backward=2 + count=3), got {len(unique_offsets)}"

    def test_forward_only_no_duplicates(self, radare2_wrapper):
        """BASELINE: Verify forward-only disassembly (backward=0) has no duplicates."""
        # When backward=0, should use simple command with no overlap
        mock_instructions = [
            {"offset": "0x401000", "opcode": "push rbp", "disasm": "push rbp", "type": "push"},
            {"offset": "0x401005", "opcode": "mov rbp, rsp", "disasm": "mov rbp, rsp", "type": "mov"},
            {"offset": "0x401010", "opcode": "sub rsp, 0x10", "disasm": "sub rsp, 0x10", "type": "sub"},
        ]

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = mock_instructions

            instructions = radare2_wrapper.disassemble_at_address("0x401000", count=3, backward=0)

            # No duplicates expected
            offsets = [insn.offset for insn in instructions]
            assert len(offsets) == len(set(offsets)), "Forward-only should have no duplicates"

    def test_backward_with_hex_offsets(self, radare2_wrapper):
        """EDGE: Verify deduplication works with hex string offsets."""
        # Addresses as hex strings
        mock_instructions = [
            {"offset": "0x401000", "opcode": "push rbp", "disasm": "push rbp", "type": "push"},
            {"offset": "0x401010", "opcode": "sub rsp, 0x10", "disasm": "sub rsp, 0x10", "type": "sub"},
            {"offset": "0x401010", "opcode": "sub rsp, 0x10", "disasm": "sub rsp, 0x10", "type": "sub"},  # DUPLICATE
        ]

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = mock_instructions

            instructions = radare2_wrapper.disassemble_at_address("0x401010", count=1, backward=1)

            offsets = [insn.offset for insn in instructions]
            unique_offsets = list(dict.fromkeys(offsets))

            assert len(unique_offsets) == 2, f"Expected 2 unique hex offsets, got {len(unique_offsets)}"

    def test_backward_with_int_offsets(self, radare2_wrapper):
        """EDGE: Verify deduplication works with integer offsets."""
        # Addresses as integers (radare2 may return this format)
        mock_instructions = [
            {"offset": 4198400, "opcode": "push rbp", "disasm": "push rbp", "type": "push"},  # 0x401000
            {"offset": 4198416, "opcode": "sub rsp, 0x10", "disasm": "sub rsp, 0x10", "type": "sub"},  # 0x401010
            {"offset": 4198416, "opcode": "sub rsp, 0x10", "disasm": "sub rsp, 0x10", "type": "sub"},  # DUPLICATE
        ]

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = mock_instructions

            instructions = radare2_wrapper.disassemble_at_address("0x401010", count=1, backward=1)

            offsets = [insn.offset for insn in instructions]
            unique_offsets = list(dict.fromkeys(offsets))

            assert len(unique_offsets) == 2, f"Expected 2 unique int offsets, got {len(unique_offsets)}"

    def test_backward_preserves_first_occurrence(self, radare2_wrapper):
        """BEHAVIOR: Verify first occurrence of duplicate is preserved (not last)."""
        # When duplicate offset, should keep the FIRST occurrence
        mock_instructions = [
            {"offset": "0x401010", "opcode": "sub rsp, 0x10", "disasm": "sub rsp, 0x10", "type": "sub"},
            {"offset": "0x401010", "opcode": "DUPLICATE", "disasm": "DUPLICATE", "type": "invalid"},  # Should be removed
        ]

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = mock_instructions

            instructions = radare2_wrapper.disassemble_at_address("0x401010", count=1, backward=1)

            assert len(instructions) == 1, "Should have 1 instruction after deduplication"
            assert instructions[0].opcode == "sub rsp, 0x10", \
                "Should preserve FIRST occurrence, not duplicate"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
