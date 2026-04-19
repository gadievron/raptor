"""Unit tests for packages.binary_analysis._validators."""

import pytest

from packages.binary_analysis._validators import (
    is_valid_hex_address,
    validate_byte_count,
    validate_hex_address,
)


class TestIsValidHexAddress:
    @pytest.mark.parametrize("addr", [
        "0x0", "0xdeadbeef", "0xDEADBEEF", "0x7fff5fbff000",
        "0x" + "f" * 16,
    ])
    def test_valid(self, addr):
        assert is_valid_hex_address(addr)

    @pytest.mark.parametrize("addr", [
        "", "0x", "deadbeef", "0xg00d", "0x1234 extra",
        "0x1234\nshell id", "0x" + "f" * 17,
        None, 0xdeadbeef, 12345,
    ])
    def test_invalid(self, addr):
        assert not is_valid_hex_address(addr)


class TestValidateHexAddress:
    def test_valid_passes(self):
        validate_hex_address("0xdeadbeef")

    def test_newline_raises_valueerror(self):
        with pytest.raises(ValueError, match="Invalid address"):
            validate_hex_address("0x1234\nshell id")

    def test_overlong_raises(self):
        with pytest.raises(ValueError, match="Invalid address"):
            validate_hex_address("0x" + "a" * 17)

    def test_non_str_raises_valueerror_not_typeerror(self):
        """re.match raises TypeError on non-str; we want consistent ValueError."""
        with pytest.raises(ValueError, match="expected str"):
            validate_hex_address(0xdeadbeef)
        with pytest.raises(ValueError, match="expected str"):
            validate_hex_address(None)

    def test_param_name_in_message(self):
        with pytest.raises(ValueError, match="Invalid crash_address"):
            validate_hex_address("nope", param_name="crash_address")


class TestValidateByteCount:
    @pytest.mark.parametrize("n", [1, 64, 4096])
    def test_valid(self, n):
        validate_byte_count(n)

    @pytest.mark.parametrize("n", [0, -1, 4097])
    def test_out_of_range(self, n):
        with pytest.raises(ValueError, match="between 1 and 4096"):
            validate_byte_count(n)

    def test_string_rejected(self):
        """The bug the review flagged: str that looks like an int."""
        with pytest.raises(ValueError, match="expected int"):
            validate_byte_count("64")
        with pytest.raises(ValueError, match="expected int"):
            validate_byte_count("64\nshell id")

    def test_bool_rejected(self):
        """bool is an int subclass; explicit reject."""
        with pytest.raises(ValueError, match="expected int"):
            validate_byte_count(True)
