"""Invalid witness integers retain bounded range diagnostics."""

import sys

import pytest

from core.smt_solver.witness import bv_to_int


@pytest.mark.parametrize("raw", [1 << 20000, -(1 << 20000)], ids=["positive", "negative"])
@pytest.mark.parametrize("width", [8, 30000])
def test_large_invalid_raw_integer_keeps_the_range_refusal(raw, width):
    if raw >= 0 and width > raw.bit_length():
        assert bv_to_int(raw, width, False) == raw
        return
    limit = sys.get_int_max_str_digits()
    with pytest.raises(ValueError) as caught:
        bv_to_int(raw, width, False)
    message = str(caught.value)
    assert message.startswith("bv_to_int: raw=<20001-bit ")
    assert ("negative integer>" if raw < 0 else "nonnegative integer>") in message
    assert "out of range [0," in message
    assert f"for width={width}" in message
    assert len(message) < 200
    assert sys.get_int_max_str_digits() == limit


@pytest.mark.parametrize("raw", [-1, 256, 257, -(1 << 1000)])
def test_small_raw_values_keep_existing_diagnostic_text(raw):
    with pytest.raises(ValueError) as caught:
        bv_to_int(raw, 8, False)
    assert str(caught.value) == f"bv_to_int: raw={raw} out of range [0, 256) for width=8"


def test_wide_valid_signed_value_is_still_reinterpreted_exactly():
    raw = 1 << 20000
    assert bv_to_int(raw, 20001, False) == raw
    assert bv_to_int(raw, 20001, True) == -raw
