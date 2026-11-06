"""Generated display aliases cannot borrow a real model declaration's name."""

from itertools import permutations

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver.witness import format_vars, format_witness  # noqa: E402


@pytest.mark.parametrize("order", list(permutations(range(3))))
def test_every_traversal_order_preserves_a_real_suffix_name(order):
    declarations = [(z3.BitVec("x", 8), 255), (z3.BitVec("x", 16), 65535), (z3.BitVec("x__1", 8), 7)]
    model = z3.Model()
    for index in order:
        variable, value = declarations[index]
        model.update_value(variable.decl(), z3.BitVecVal(value, variable.size()))
    result = format_witness(model, {"x": True, "x__1": False})
    assert result == {"x": -1, "x__1": 7, "x__2": -1}
    assert format_vars(model, {"source_input": declarations[2][0]}, False) == {"source_input": 7}


def test_non_bitvector_declaration_names_are_reserved_too():
    model = z3.Model()
    for width in (8, 16):
        model.update_value(z3.BitVec("x", width).decl(), z3.BitVecVal(1, width))
    model.update_value(z3.Int("x__1").decl(), z3.IntVal(9))
    result = format_witness(model, False)
    assert result == {"x": 1, "x__2": 1}


def test_gaps_and_large_natural_suffixes_do_not_rename_source_variables():
    model = z3.Model()
    for width in (8, 16, 32):
        model.update_value(z3.BitVec("Value", width).decl(), z3.BitVecVal(1, width))
    for name in ("Value__1", "Value__3", "Value__99999999999999999999"):
        model.update_value(z3.BitVec(name, 8).decl(), z3.BitVecVal(7, 8))
    result = format_witness(model, False)
    assert result["Value__1"] == result["Value__3"] == result["Value__99999999999999999999"] == 7
    assert result["Value__2"] == result["Value__4"] == 1
    assert len(result) == 6
