"""Signedness resolution for collision-suffixed witness variables.

Same-named z3 decls (e.g. an 8-bit and a 16-bit ``x`` from two parsed
expressions) are disambiguated with a ``__N`` suffix in the witness
output — but the caller's signedness map is keyed by DECLARATION
names, so the lookup must use the base name. Looking up the suffixed
name missed the map entry and silently rendered the second decl
unsigned.
"""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver.witness import format_witness  # noqa: E402


def _model_with_same_named_decls():
    x8 = z3.BitVec("x", 8)
    x16 = z3.BitVec("x", 16)
    solver = z3.Solver()
    solver.add(x8 == z3.BitVecVal(0xF0, 8))
    solver.add(x16 == z3.BitVecVal(0xFFF0, 16))
    assert solver.check() == z3.sat
    return solver.model()


def test_suffixed_decl_resolves_signedness_on_base_name():
    model = _model_with_same_named_decls()
    out = format_witness(model, {"x": True})
    assert set(out) == {"x", "x__1"}
    # Both carry the base name "x", so BOTH render signed.
    assert out["x"] == -16
    assert out["x__1"] == -16


def test_unmapped_base_name_stays_unsigned_for_both():
    model = _model_with_same_named_decls()
    out = format_witness(model, {})
    assert sorted(out) == ["x", "x__1"]
    assert all(v > 0 for v in out.values())
