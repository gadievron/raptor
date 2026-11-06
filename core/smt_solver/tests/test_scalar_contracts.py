"""Malformed scalar arguments cannot silently choose a different SMT model."""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import BVProfile, bv_to_int, ge, gt, le, lt, mk_val, mk_var  # noqa: E402
from core.smt_solver import csem  # noqa: E402
from core.smt_solver.witness import format_vars, format_witness  # noqa: E402

BAD_FLAGS = ["false", "true", 0, 1, None, [], {}]
BAD_WIDTHS = [True, False, 8.0, "8", None, 0, -1]


@pytest.mark.parametrize("signed", BAD_FLAGS)
@pytest.mark.parametrize("compare", [le, lt, ge, gt], ids=["le", "lt", "ge", "gt"])
def test_comparisons_decline_non_boolean_signedness(compare, signed):
    with pytest.raises(ValueError, match="signed.*boolean"):
        compare(z3.BitVecVal(255, 8), z3.BitVecVal(0, 8), signed)


@pytest.mark.parametrize("flag", BAD_FLAGS)
@pytest.mark.parametrize("action", ["cast", "source", "destination", "witness", "completion"])
def test_flags_are_validated_at_every_semantic_boundary(flag, action):
    value = z3.BitVecVal(255, 8)
    with pytest.raises(ValueError, match="boolean"):
        if action == "cast":
            csem.cast(value, 8, from_signed=flag)  # same-width must validate too
        elif action == "source":
            csem.truncation_loses_bits(value, 4, to_signed=True, from_signed=flag)
        elif action == "destination":
            csem.truncation_loses_bits(value, 4, to_signed=flag, from_signed=False)
        elif action == "witness":
            bv_to_int(255, 8, flag)
        else:
            format_vars(z3.Model(), {"unused": z3.BitVec("unused", 8)}, False, completion=flag)


@pytest.mark.parametrize("width", BAD_WIDTHS)
@pytest.mark.parametrize("action", ["profile", "variable", "value", "cast", "truncate", "sign", "zero", "witness"])
def test_bit_widths_are_exact_positive_integers(width, action):
    value = z3.BitVecVal(255, 8)
    with pytest.raises(ValueError, match="positive.*integer"):
        if action == "profile":
            BVProfile(width)
        elif action == "variable":
            mk_var("Value", width)
        elif action == "value":
            mk_val(1, width)
        elif action == "cast":
            csem.cast(value, width, False)
        elif action == "truncate":
            csem.truncate(value, width)
        elif action == "sign":
            csem.sign_extend(value, width)
        elif action == "zero":
            csem.zero_extend(value, width)
        else:
            bv_to_int(0, width, False)


@pytest.mark.parametrize("value", [True, False, 1.0, "1", None])
@pytest.mark.parametrize("action", [mk_val, bv_to_int], ids=["construct", "interpret"])
def test_values_are_integers_without_bool_or_string_coercion(value, action):
    with pytest.raises(ValueError, match="integer"):
        if action is mk_val:
            action(value, 8)
        else:
            action(value, 8, False)


@pytest.mark.parametrize("formatter", [format_witness, format_vars])
@pytest.mark.parametrize("signed", ["false", 0, 1, None, {"unused": "false"}, {"unused": 0}, {1: False}])
def test_signedness_maps_are_checked_even_when_the_model_is_empty(formatter, signed):
    with pytest.raises(ValueError, match="boolean|names must be strings"):
        if formatter is format_vars:
            formatter(z3.Model(), {}, signed)
        else:
            formatter(z3.Model(), signed)


@pytest.mark.parametrize("value,expected", [(-1, 255), (256, 0), (257, 1)])
def test_explicit_integer_bit_pattern_construction_remains_modular(value, expected):
    assert z3.simplify(mk_val(value, 8)).as_long() == expected


def test_valid_false_completion_does_not_fill_a_free_variable():
    free = z3.BitVec("Free", 8)
    model = z3.Model()
    assert format_vars(model, {"Free": free}, False, completion=False) == {}
    assert format_vars(model, {"Free": free}, False, completion=True) == {"Free": 0}
