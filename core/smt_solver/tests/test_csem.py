"""Tests for core.smt_solver.csem — C-semantics bitvector helpers."""

import sys
from pathlib import Path

import pytest

# core/smt_solver/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.smt_solver import z3_available
from core.smt_solver._testing import eval_bv as _eval_bv, eval_predicate as _eval_predicate

_requires_z3 = pytest.mark.skipif(
    not z3_available(),
    reason="z3-solver not installed",
)


# ---------------------------------------------------------------------------
# Width coercion
# ---------------------------------------------------------------------------

class TestWidthCoercion:
    @_requires_z3
    def test_truncate_keeps_low_bits(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import truncate
        assert _eval_bv(truncate(z3.BitVecVal(0xFFEE, 16), 8), 8) == 0xEE

    @_requires_z3
    def test_sign_extend_preserves_sign(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import sign_extend
        # 0xFE as int8 = -2; sign-extended to 32 bits = 0xFFFFFFFE
        assert _eval_bv(sign_extend(z3.BitVecVal(0xFE, 8), 32), 32) == 0xFFFFFFFE

    @_requires_z3
    def test_zero_extend_pads_with_zero(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import zero_extend
        assert _eval_bv(zero_extend(z3.BitVecVal(0xFE, 8), 32), 32) == 0x000000FE

    @_requires_z3
    def test_truncation_loses_bits_unsigned_lossless(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import truncation_loses_bits
        # 0x7F fits in 8-bit unsigned
        assert _eval_predicate(
            z3.Not(truncation_loses_bits(z3.BitVecVal(0x7F, 32), 8, to_signed=False))
        )

    @_requires_z3
    def test_truncation_loses_bits_unsigned_lossy(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import truncation_loses_bits
        # 0x1FF doesn't fit in 8-bit unsigned (max 0xFF)
        assert _eval_predicate(
            truncation_loses_bits(z3.BitVecVal(0x1FF, 32), 8, to_signed=False)
        )

    @_requires_z3
    def test_truncation_loses_bits_signed_lossy(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import truncation_loses_bits
        # 0xFFFFFF7F as int32 = -129; narrow int8 is 0x7F = +127; values differ
        assert _eval_predicate(
            truncation_loses_bits(z3.BitVecVal(0xFFFFFF7F, 32), 8, to_signed=True)
        )


# ---------------------------------------------------------------------------
# Overflow predicates
# ---------------------------------------------------------------------------

class TestOverflowPredicates:
    @_requires_z3
    def test_uadd_overflows_when_wraps(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import uadd_overflows
        # 0xFF + 1 in 8-bit unsigned wraps to 0
        assert _eval_predicate(uadd_overflows(z3.BitVecVal(0xFF, 8), z3.BitVecVal(1, 8)))

    @_requires_z3
    def test_uadd_overflows_false_when_safe(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import uadd_overflows
        assert _eval_predicate(
            z3.Not(uadd_overflows(z3.BitVecVal(1, 8), z3.BitVecVal(1, 8)))
        )

    @_requires_z3
    def test_sadd_overflows_positive_to_negative(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import sadd_overflows
        # 0x7F (int8 max = 127) + 1 overflows to 0x80 (-128)
        assert _eval_predicate(sadd_overflows(z3.BitVecVal(0x7F, 8), z3.BitVecVal(1, 8)))

    @_requires_z3
    def test_sadd_overflows_negative_to_positive(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import sadd_overflows
        # 0x80 (int8 = -128) + 0xFF (int8 = -1) underflows to 0x7F (+127)
        assert _eval_predicate(sadd_overflows(z3.BitVecVal(0x80, 8), z3.BitVecVal(0xFF, 8)))

    @_requires_z3
    def test_sadd_overflows_safe(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import sadd_overflows
        assert _eval_predicate(
            z3.Not(sadd_overflows(z3.BitVecVal(1, 8), z3.BitVecVal(1, 8)))
        )

    @_requires_z3
    def test_usub_underflows(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import usub_underflows
        # 1 - 2 in 8-bit unsigned wraps to 0xFF
        assert _eval_predicate(usub_underflows(z3.BitVecVal(1, 8), z3.BitVecVal(2, 8)))

    @_requires_z3
    def test_usub_underflows_safe(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import usub_underflows
        assert _eval_predicate(
            z3.Not(usub_underflows(z3.BitVecVal(10, 8), z3.BitVecVal(2, 8)))
        )

    @_requires_z3
    def test_ssub_overflows(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import ssub_overflows
        # 0x80 (-128) - 1 underflows to 0x7F (+127)
        assert _eval_predicate(ssub_overflows(z3.BitVecVal(0x80, 8), z3.BitVecVal(1, 8)))

    @_requires_z3
    def test_umul_overflows_32bit_alloc_case(self):
        """ALLOC testbench case: count * 16 wraps at 32-bit."""
        from core.smt_solver import z3
        from core.smt_solver.csem import umul_overflows
        assert _eval_predicate(
            umul_overflows(z3.BitVecVal(0x10000001, 32), z3.BitVecVal(16, 32))
        )

    @_requires_z3
    def test_umul_overflows_safe(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import umul_overflows
        assert _eval_predicate(
            z3.Not(umul_overflows(z3.BitVecVal(10, 32), z3.BitVecVal(16, 32)))
        )

    @_requires_z3
    def test_smul_overflows(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import smul_overflows
        # 0x40 (+64) * 4 in int8 = 256, wraps to 0 — signed overflow
        assert _eval_predicate(smul_overflows(z3.BitVecVal(0x40, 8), z3.BitVecVal(4, 8)))


# ---------------------------------------------------------------------------
# Shift disambiguators
# ---------------------------------------------------------------------------

class TestShifts:
    @_requires_z3
    def test_ashr_preserves_sign_bit(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import ashr
        # 0x80 (int8 = -128) >> 1 arithmetic = 0xC0 (-64)
        assert _eval_bv(ashr(z3.BitVecVal(0x80, 8), z3.BitVecVal(1, 8)), 8) == 0xC0

    @_requires_z3
    def test_lshr_zero_fills(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import lshr
        # 0x80 >> 1 logical = 0x40 (zero shifted into high bit)
        assert _eval_bv(lshr(z3.BitVecVal(0x80, 8), z3.BitVecVal(1, 8)), 8) == 0x40

    @_requires_z3
    def test_ashr_and_lshr_agree_on_positive(self):
        """For values with the sign bit clear, arithmetic and logical shift match."""
        from core.smt_solver import z3
        from core.smt_solver.csem import ashr, lshr
        v = z3.BitVecVal(0x40, 8)  # high bit clear
        assert _eval_bv(ashr(v, z3.BitVecVal(1, 8)), 8) == _eval_bv(lshr(v, z3.BitVecVal(1, 8)), 8)


# ---------------------------------------------------------------------------
# Cast
# ---------------------------------------------------------------------------

class TestCast:
    @_requires_z3
    def test_cast_widen_signed_sign_extends(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import cast
        assert _eval_bv(cast(z3.BitVecVal(0xFE, 8), to_width=32, from_signed=True), 32) == 0xFFFFFFFE

    @_requires_z3
    def test_cast_widen_unsigned_zero_extends(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import cast
        assert _eval_bv(cast(z3.BitVecVal(0xFE, 8), to_width=32, from_signed=False), 32) == 0x000000FE

    @_requires_z3
    def test_cast_narrow_truncates(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import cast
        assert _eval_bv(cast(z3.BitVecVal(0x1234, 16), to_width=8, from_signed=False), 8) == 0x34

    @_requires_z3
    def test_cast_same_width_noop(self):
        from core.smt_solver import z3
        from core.smt_solver.csem import cast
        v = z3.BitVecVal(0x42, 8)
        assert _eval_bv(cast(v, to_width=8, from_signed=False), 8) == 0x42
