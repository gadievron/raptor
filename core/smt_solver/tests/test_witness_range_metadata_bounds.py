"""Witness integer conversion is metadata work, independent of native width."""

import pytest

from core.smt_solver.witness import bv_to_int


def test_large_width_range_error_does_not_render_a_width_sized_bound():
    with pytest.raises(ValueError) as caught:
        bv_to_int(-1, 5000, False)
    assert 'out of range' in str(caught.value)
    assert '2**5000' in str(caught.value)
    assert len(str(caught.value)) < 200


@pytest.mark.parametrize('width', range(1, 13))
@pytest.mark.parametrize('signed', [False, True])
def test_small_width_conversion_matches_twos_complement_oracle(width, signed):
    upper = 1 << width
    for raw in {-1, 0, 1, (upper >> 1) - 1, upper >> 1, upper - 1, upper, upper + 1}:
        if not 0 <= raw < upper:
            with pytest.raises(ValueError, match='out of range'):
                bv_to_int(raw, width, signed)
        else:
            expected = raw - upper if signed and raw >= upper >> 1 else raw
            assert bv_to_int(raw, width, signed) == expected


@pytest.mark.parametrize('signed', [False, True])
def test_native_maximum_width_tiny_values_need_no_native_sort(signed):
    width = (1 << 32) - 1
    assert bv_to_int(0, width, signed) == 0
    assert bv_to_int(1, width, signed) == 1
    with pytest.raises(ValueError, match=r'2\*\*4294967295'):
        bv_to_int(-1, width, signed)


@pytest.mark.parametrize('raw', [True, False, 1.0, '1', None])
def test_raw_value_type_contract_remains_exact(raw):
    with pytest.raises(ValueError, match='raw must be an integer'):
        bv_to_int(raw, 8, False)


@pytest.mark.parametrize('width', [True, False, 0, -1, 8.0, '8', None, 1 << 32])
def test_invalid_width_still_refuses_before_conversion(width):
    with pytest.raises(ValueError):
        bv_to_int(0, width, False)


@pytest.mark.parametrize('signed', [0, 1, 'false', None])
def test_signedness_remains_an_explicit_boolean(signed):
    with pytest.raises(ValueError, match='signed must be a boolean'):
        bv_to_int(0, 8, signed)


def test_common_range_error_and_wide_negative_reinterpretation_stay_exact():
    with pytest.raises(ValueError) as caught:
        bv_to_int(256, 8, False)
    assert str(caught.value) == 'bv_to_int: raw=256 out of range [0, 256) for width=8'
    assert bv_to_int(1 << 4999, 5000, True) == -(1 << 4999)
    assert bv_to_int((1 << 5000) - 1, 5000, True) == -1
