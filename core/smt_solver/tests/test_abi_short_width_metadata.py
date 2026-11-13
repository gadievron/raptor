"""Explicit ABI metadata cannot describe an eight-bit C short."""

import pytest

from core.smt_solver.integer_abi import (
    INTEGER_ABIS, IntegerABI, integer_abi_key, resolve_integer_abi,
)
from core.smt_solver.integer_types import integer_type


def test_eight_bit_short_refuses_before_producing_an_integer_type():
    fields = dict(name="invalid-short", char_bits=8, short_bits=8, int_bits=16,
                  long_bits=32, long_long_bits=64, representation="twos-complement-no-padding")
    with pytest.raises(ValueError, match="inconsistent integer ABI widths"):
        IntegerABI(**fields)
    assert resolve_integer_abi(fields) is None
    assert integer_type("short", fields) is None
    assert integer_type("unsigned short", fields) is None
    assert integer_abi_key(fields) == "unknown"


@pytest.mark.parametrize("name", sorted(INTEGER_ABIS))
def test_named_abi_short_domains_are_unchanged(name):
    abi = INTEGER_ABIS[name]
    assert resolve_integer_abi(name) is abi
    assert resolve_integer_abi(abi.record()) == abi
    assert integer_type("short", abi).width == abi.short_bits
    assert integer_type("unsigned short", abi).width == abi.short_bits


@pytest.mark.parametrize("width", [16, 32, 64])
def test_equal_character_and_short_widths_remain_supported(width):
    abi = IntegerABI("wide-char", width, width, width, max(width, 32), 64,
                     "twos-complement-no-padding")
    assert resolve_integer_abi(abi.record()) == abi
    signed = integer_type("short", abi)
    unsigned = integer_type("unsigned short", abi)
    assert signed.width == unsigned.width == width
    assert signed.signed is True and unsigned.signed is False
    assert signed.promoted_signed is True
    assert unsigned.promoted_signed is False
