"""Literal range checks stay bounded by token size, without native sorts."""

import pytest

from core.smt_solver.config import BVProfile
from core.smt_solver.rejection import Rejection, RejectionKind, parse_literal_value


def test_wide_profile_rejection_detail_does_not_expand_numeric_endpoints():
    result = parse_literal_value('-1', BVProfile(5000, False), outer_text='Value == -1')
    assert isinstance(result, Rejection)
    assert result.kind == RejectionKind.LITERAL_OUT_OF_RANGE
    assert result.text == 'Value == -1'
    assert len(result.detail) < 256
    assert '2**5000' in result.detail


@pytest.mark.parametrize('width', [1, 2, 7, 8, 16, 32, 64, 257])
@pytest.mark.parametrize('signed', [False, True])
def test_decimal_boundaries_match_integer_range_oracle(width, signed):
    profile = BVProfile(width, signed)
    lower = -(1 << (width - 1)) if signed else 0
    upper = (1 << (width - 1)) - 1 if signed else (1 << width) - 1
    for value in {lower - 1, lower, lower + 1, -1, 0, 1, upper - 1, upper, upper + 1}:
        result = parse_literal_value(str(value), profile)
        if lower <= value <= upper:
            assert type(result) is int and result == value
        else:
            assert isinstance(result, Rejection)
            assert result.kind == RejectionKind.LITERAL_OUT_OF_RANGE


@pytest.mark.parametrize('width', [1, 7, 8, 16, 64, 257])
@pytest.mark.parametrize('signed', [False, True])
def test_hex_bit_patterns_keep_full_width_independent_of_signedness(width, signed):
    profile = BVProfile(width, signed)
    for value in {0, 1, (1 << width) - 1, 1 << width}:
        result = parse_literal_value(hex(value), profile)
        if value < 1 << width:
            assert type(result) is int and result == value
        else:
            assert isinstance(result, Rejection)
            assert result.kind == RejectionKind.LITERAL_OUT_OF_RANGE


@pytest.mark.parametrize('token,signed,expected', [('0', False, 0), ('1', True, 1), ('-1', True, -1), ('0xffff', True, 65535)])
def test_native_maximum_width_metadata_accepts_tiny_literals_without_sort_allocation(token, signed, expected):
    # Only profile metadata and Python integers are used; no native expression
    # or solver is constructed at this admitted width.
    profile = BVProfile((1 << 32) - 1, signed)
    assert parse_literal_value(token, profile) == expected


def test_native_maximum_unsigned_negative_literal_keeps_bounded_refusal():
    result = parse_literal_value('-1', BVProfile((1 << 32) - 1, False))
    assert isinstance(result, Rejection)
    assert result.kind == RejectionKind.LITERAL_OUT_OF_RANGE
    assert len(result.detail) < 256
    assert '2**4294967295' in result.detail


def test_ordinary_profile_rejection_keeps_existing_numeric_range_detail():
    result = parse_literal_value('-1', BVProfile(8, False))
    assert isinstance(result, Rejection)
    assert result.detail.endswith('(0x0..0xff)')
