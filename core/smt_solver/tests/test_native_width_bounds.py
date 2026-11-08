"""Python widths cannot wrap in Z3's unsigned native arguments."""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import BVProfile, mk_val, mk_var  # noqa: E402
from core.smt_solver import csem  # noqa: E402
from core.smt_solver._validation import require_width  # noqa: E402


@pytest.mark.parametrize("width", [1 << 32, (1 << 32) + 8, (1 << 64) + 8])
@pytest.mark.parametrize("boundary", [
    "profile", "variable", "literal", "cast", "sign", "zero", "truncate",
    "conversion", "truncation", "shift-count",
])
def test_unrepresentable_widths_decline_before_native_integer_coercion(width, boundary):
    value = z3.BitVecVal(255, 8)
    with pytest.raises(ValueError, match="native unsigned 32-bit width limit"):
        if boundary == "profile":
            BVProfile(width)
        elif boundary == "variable":
            mk_var("Value", width)
        elif boundary == "literal":
            mk_val(1, width)
        elif boundary == "cast":
            csem.cast(value, width, False)
        elif boundary == "sign":
            csem.sign_extend(value, width)
        elif boundary == "zero":
            csem.zero_extend(value, width)
        elif boundary == "truncate":
            csem.truncate(value, width)
        elif boundary == "conversion":
            csem.conversion_changes_value(value, width, True, from_signed=False)
        elif boundary == "truncation":
            csem.truncation_loses_bits(value, width, True, from_signed=False)
        else:
            csem.shift_count_invalid(value, width, signed=False)


def test_native_width_boundary_is_checked_without_allocating_a_large_sort():
    # Admission is not an allocation guarantee. The boundary can be checked
    # as metadata without asking Z3 to allocate a multi-gigabit vector.
    maximum = (1 << 32) - 1
    assert require_width(maximum) == maximum
    assert BVProfile(maximum).width == maximum
    with pytest.raises(ValueError, match="native unsigned 32-bit width limit"):
        require_width(maximum + 1)


@pytest.mark.parametrize("width", [1, 7, 32, 64, 128, 257])
def test_supported_widths_retain_exact_native_sizes(width):
    variable, literal = mk_var("Value", width), mk_val(1, width)
    assert variable.size() == literal.size() == BVProfile(width).width == width
    source = mk_val(1, 1)
    assert csem.sign_extend(source, width).size() == width
    assert csem.zero_extend(source, width).size() == width
