"""Integer value preservation needs both source and destination signedness."""

from inspect import Parameter, signature

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver.csem import cast, truncation_loses_bits  # noqa: E402


def integer(raw, width, signed):
    return raw - (1 << width) if signed and raw & (1 << (width - 1)) else raw


@pytest.mark.parametrize("width", [1, 2, 3, 4, 5])
@pytest.mark.parametrize("source_signed", [False, True])
@pytest.mark.parametrize("destination_signed", [False, True])
def test_every_small_narrowing_matches_independent_integer_math(width, source_signed, destination_signed):
    for target in range(1, width + 1):
        for raw in range(1 << width):
            converted = raw % (1 << target)
            expected = integer(raw, width, source_signed) != integer(converted, target, destination_signed)
            result = z3.simplify(truncation_loses_bits(z3.BitVecVal(raw, width), target, destination_signed,
                                                      from_signed=source_signed))
            assert z3.is_true(result) is expected, (width, target, raw, source_signed, destination_signed)


@pytest.mark.parametrize("source_signed,destination_signed,expected", [
    (False, True, True), (True, True, False), (True, False, True), (False, False, True),
])
def test_same_source_bits_have_different_conversion_values(source_signed, destination_signed, expected):
    result = truncation_loses_bits(z3.BitVecVal(65535, 16), 8, destination_signed, from_signed=source_signed)
    assert z3.is_true(z3.simplify(result)) is expected


@pytest.mark.parametrize("source_signed,destination_signed,expected", [(False, True, True), (True, False, True),
                                                                     (True, True, False), (False, False, False)])
def test_same_width_reinterpretation_can_change_the_integer_value(source_signed, destination_signed, expected):
    result = truncation_loses_bits(z3.BitVecVal(255, 8), 8, destination_signed, from_signed=source_signed)
    assert z3.is_true(z3.simplify(result)) is expected


@pytest.mark.parametrize("width,target", [(16, 8), (32, 16), (64, 32), (64, 64), (128, 64)])
@pytest.mark.parametrize("source_signed", [False, True])
@pytest.mark.parametrize("destination_signed", [False, True])
def test_conversion_boundary_values_cover_wide_inputs(width, target, source_signed, destination_signed):
    values = {0, 1, (1 << width) - 1, 1 << (width - 1), (1 << (width - 1)) - 1,
              (1 << target) - 1, 1 << (target - 1), (1 << (target - 1)) - 1}
    for raw in values:
        expected = integer(raw, width, source_signed) != integer(raw % (1 << target), target, destination_signed)
        result = truncation_loses_bits(z3.BitVecVal(raw, width), target, destination_signed, from_signed=source_signed)
        assert z3.is_true(z3.simplify(result)) is expected


def test_source_signedness_is_required_instead_of_guessed():
    parameter = signature(truncation_loses_bits).parameters["from_signed"]
    assert parameter.default is Parameter.empty
    assert parameter.kind is Parameter.KEYWORD_ONLY


@pytest.mark.parametrize("width,target", [(4, 8), (8, 4), (8, 8)])
@pytest.mark.parametrize("signed", [False, True])
def test_cast_bit_patterns_still_match_modular_conversion(width, target, signed):
    for raw in range(1 << width):
        expected = integer(raw, width, signed) % (1 << target)
        actual = z3.simplify(cast(z3.BitVecVal(raw, width), target, signed)).as_long()
        assert actual == expected


def test_solver_finds_the_previously_missed_unsigned_to_signed_value_change():
    from core.smt_solver import format_vars, new_solver
    value = z3.BitVec("Value", 16)
    solver = new_solver()
    solver.add(z3.UGE(value, z3.BitVecVal(65408, 16)))
    solver.add(truncation_loses_bits(value, 8, to_signed=True, from_signed=False))
    assert solver.check() == z3.sat
    raw = format_vars(solver.model(), {"Value": value}, signed=False)["Value"]
    assert 65408 <= raw <= 65535
    assert raw != integer(raw % 256, 8, True)


@pytest.mark.parametrize("source_signed", [False, True])
def test_solver_proves_a_value_preserving_signed_destination_range(source_signed):
    from core.smt_solver import ge, le, new_solver
    value = z3.BitVec("Value", 16)
    solver = new_solver()
    solver.add(ge(value, z3.BitVecVal(-128 if source_signed else 0, 16), signed=source_signed))
    solver.add(le(value, z3.BitVecVal(127, 16), signed=source_signed))
    solver.add(truncation_loses_bits(value, 8, to_signed=True, from_signed=source_signed))
    assert solver.check() == z3.unsat
