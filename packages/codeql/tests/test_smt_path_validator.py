"""Tests for packages.codeql.smt_path_validator."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# packages/codeql/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.smt_solver import RejectionKind, z3_available
from packages.codeql.smt_path_validator import (
    PathCondition,
    PathSMTResult,
    check_path_feasibility,
)

_requires_z3 = pytest.mark.skipif(
    not z3_available(),
    reason="z3-solver not installed",
)


# ---------------------------------------------------------------------------
# check_path_feasibility — no Z3
# ---------------------------------------------------------------------------

class TestNoZ3:
    """Behaviour when Z3 is unavailable — must degrade gracefully."""

    def test_returns_none_feasible(self):
        with patch("packages.codeql.smt_path_validator._z3_available", return_value=False):
            r = check_path_feasibility([PathCondition("size > 0", step_index=0)])
        assert r.feasible is None
        assert r.smt_available is False

    def test_all_conditions_go_to_unknown(self):
        conditions = [
            PathCondition("size > 0", step_index=0),
            PathCondition("offset < 1024", step_index=1),
        ]
        with patch("packages.codeql.smt_path_validator._z3_available", return_value=False):
            r = check_path_feasibility(conditions)
        assert set(r.unknown) == {"size > 0", "offset < 1024"}

    def test_empty_conditions_still_returns_none(self):
        with patch("packages.codeql.smt_path_validator._z3_available", return_value=False):
            r = check_path_feasibility([])
        assert r.feasible is None
        assert r.smt_available is False


# ---------------------------------------------------------------------------
# check_path_feasibility — with Z3
# ---------------------------------------------------------------------------

class TestFeasibility:
    """Core sat/unsat/unknown results."""

    @_requires_z3
    def test_empty_conditions_feasible(self):
        r = check_path_feasibility([])
        assert r.feasible is True
        assert r.smt_available is True

    @_requires_z3
    def test_satisfiable_range(self):
        """size > 0 AND size < 1024 — clearly satisfiable."""
        r = check_path_feasibility([
            PathCondition("size > 0", step_index=0),
            PathCondition("size < 1024", step_index=1),
        ])
        assert r.feasible is True
        assert "size" in r.model
        assert 0 < r.model["size"] < 1024

    @_requires_z3
    def test_infeasible_contradiction(self):
        """size > 0 AND size < 0 — mutually exclusive."""
        r = check_path_feasibility([
            PathCondition("size > 0", step_index=0),
            PathCondition("size < 0", step_index=1),
        ])
        assert r.feasible is False
        assert len(r.unsatisfied) >= 1

    @_requires_z3
    def test_infeasible_names_conflicting_conditions(self):
        """Unsat core must name the specific conflicting conditions."""
        r = check_path_feasibility([
            PathCondition("size > 100", step_index=0),
            PathCondition("size < 50", step_index=1),
        ])
        assert r.feasible is False
        assert "size > 100" in r.unsatisfied or "size < 50" in r.unsatisfied

    @_requires_z3
    def test_unparseable_condition_goes_to_unknown(self):
        """Function-call syntax is rejected by the parser — goes to unknown, not crash."""
        r = check_path_feasibility([
            PathCondition("size > 0", step_index=0),
            PathCondition("validate(ptr, len) == 0", step_index=1),
        ])
        assert "validate(ptr, len) == 0" in r.unknown
        # The parseable condition still runs; result is sat or None, not outright infeasible
        assert r.feasible is not False

    @_requires_z3
    def test_all_unknown_returns_none(self):
        """If nothing is parseable, feasible must be None (not True)."""
        r = check_path_feasibility([
            PathCondition("foo(bar) > baz(qux)", step_index=0),
        ])
        assert r.feasible is None

    @_requires_z3
    @pytest.mark.parametrize("expr", [
        "~mask == 0xFFFFFFFF",  # unary NOT silently dropped → would become "mask == ..."
        "a ^ b == 0",            # XOR silently dropped → "a b == 0" (orphan caught)
        "a / b > 0",             # division silently dropped
        "a % 16 == 0",           # modulo silently dropped
        "x | ~y == 0",           # NOT inside expression
        "p ? q : r == 0",        # ternary silently dropped
    ])
    def test_silently_dropped_chars_go_to_unknown(self, expr):
        """The tokeniser only matches a fixed set of operator characters;
        anything outside that set ('~', '^', '/', '%', '?', ':') would
        otherwise vanish from the token stream and produce a wrong
        encoding.  The full-input-consumed sanity check rejects these."""
        r = check_path_feasibility([PathCondition(expr, step_index=0)])
        assert expr in r.unknown, (
            f"silently-dropped chars in {expr!r} were not rejected; "
            f"this is the same class of bug as the operator-precedence "
            f"silent mis-encoding caught in PR #206."
        )

    @_requires_z3
    def test_literal_too_wide_for_profile_goes_to_unknown(self):
        """``x == 0x100`` at uint8 would silently wrap to ``x == 0`` since
        Z3's BitVecVal truncates modulo width.  The verdict ``feasible:
        true with x=0`` would mislead the caller about what was checked.
        Refuse instead — the profile is wrong for this literal."""
        from core.smt_solver import BVProfile
        r = check_path_feasibility(
            [PathCondition("x == 0x100", step_index=0)],
            profile=BVProfile(width=8, signed=False),
        )
        assert "x == 0x100" in r.unknown

    @_requires_z3
    def test_literal_at_width_boundary_fits(self):
        """``x == 0xFF`` at uint8 is exactly the max — must still be accepted."""
        from core.smt_solver import BVProfile
        r = check_path_feasibility(
            [PathCondition("x == 0xFF", step_index=0)],
            profile=BVProfile(width=8, signed=False),
        )
        assert r.feasible is True
        assert r.model["x"] == 0xFF

    @_requires_z3
    def test_leading_zero_decimal_goes_to_unknown(self):
        """``01234`` looks decimal but in C is octal (=668).  Accepting as
        base-10 silently mis-encodes; reject and let the caller use hex
        instead."""
        r = check_path_feasibility([PathCondition("x == 01234", step_index=0)])
        assert "x == 01234" in r.unknown

    @_requires_z3
    def test_bare_zero_decimal_accepted(self):
        """``0`` (single digit) is unambiguous — must still parse."""
        r = check_path_feasibility([PathCondition("x == 0", step_index=0)])
        assert r.feasible is True
        assert r.model.get("x") == 0

    @_requires_z3
    def test_bitmask_mask_too_wide_for_profile_goes_to_unknown(self):
        """The bitmask form (``flags & MASK == VAL``) extracts MASK and
        VAL via its own regex rather than going through ``atom()`` — the
        same width-range check must apply or 0x100 at uint8 silently
        wraps to 0, producing a false tautology."""
        from core.smt_solver import BVProfile
        r = check_path_feasibility(
            [PathCondition("flags & 0x100 == 0", step_index=0)],
            profile=BVProfile(width=8, signed=False),
        )
        assert "flags & 0x100 == 0" in r.unknown

    @_requires_z3
    def test_bitmask_leading_zero_mask_goes_to_unknown(self):
        """Leading-zero literals in the bitmask path used to crash
        ``int(tok, 0)`` with a Python ValueError on tokens like '010';
        now they're rejected cleanly to ``unknown``."""
        r = check_path_feasibility([PathCondition("flags & 010 == 0", step_index=0)])
        assert "flags & 010 == 0" in r.unknown

    @_requires_z3
    def test_bitmask_leading_zero_rhs_goes_to_unknown(self):
        r = check_path_feasibility([PathCondition("flags & 0xff == 010", step_index=0)])
        assert "flags & 0xff == 010" in r.unknown

    @_requires_z3
    def test_bitmask_normal_form_still_works(self):
        """Regression check: the bitmask-path validation tightening
        must not break valid bitmask conditions."""
        r = check_path_feasibility([PathCondition("flags & 0xff == 0", step_index=0)])
        assert r.feasible is True
        assert (r.model.get("flags", 0) & 0xff) == 0


class TestNegatedDisplay:
    """When a condition has ``negated=True``, downstream display strings
    (in ``satisfied`` / ``unsatisfied`` / unsat-core reasoning) must
    reflect what was actually asserted.  Showing the un-negated text
    confuses readers — ``"ptr != NULL ⊥ ptr > 0"`` looks consistent
    until you realise the solver actually asserted ``ptr == 0``."""

    @_requires_z3
    def test_negated_condition_shown_with_NOT_prefix_in_unsat_core(self):
        r = check_path_feasibility([
            PathCondition("ptr != NULL", step_index=0, negated=True),  # asserts ptr == 0
            PathCondition("ptr > 0", step_index=1),
        ])
        assert r.feasible is False
        # The display reflects what was asserted, not the original text.
        assert "NOT (ptr != NULL)" in r.unsatisfied
        # And the un-negated text should NOT appear (it's misleading).
        assert "ptr != NULL" not in r.unsatisfied

    @_requires_z3
    def test_non_negated_condition_displayed_as_written(self):
        """Unmodified conditions still appear verbatim."""
        r = check_path_feasibility([
            PathCondition("x > 100", step_index=0),
            PathCondition("x < 50", step_index=1),
        ])
        assert r.feasible is False
        assert "x > 100" in r.unsatisfied
        assert "x < 50" in r.unsatisfied

    @_requires_z3
    def test_negated_condition(self):
        """negated=True means the guard was bypassed (condition is false on path)."""
        # ptr != NULL with negated=True means ptr IS NULL on this path
        r = check_path_feasibility([
            PathCondition("ptr != NULL", step_index=0, negated=True),
        ])
        # ptr == NULL is satisfiable (ptr = 0)
        assert r.feasible is True

    @_requires_z3
    def test_negated_makes_path_infeasible(self):
        """ptr != NULL negated (ptr must be NULL) contradicts ptr > 0."""
        r = check_path_feasibility([
            PathCondition("ptr != NULL", step_index=0, negated=True),  # ptr == 0
            PathCondition("ptr > 0", step_index=1),                    # ptr > 0
        ])
        assert r.feasible is False


class TestConditionForms:
    """Parser coverage — each accepted condition form."""

    @_requires_z3
    def test_equality(self):
        r = check_path_feasibility([PathCondition("x == 42", step_index=0)])
        assert r.feasible is True
        assert r.model.get("x") == 42

    @_requires_z3
    def test_inequality(self):
        r = check_path_feasibility([PathCondition("x != 0", step_index=0)])
        assert r.feasible is True

    @_requires_z3
    def test_null_literal(self):
        r = check_path_feasibility([PathCondition("ptr == NULL", step_index=0)])
        assert r.feasible is True
        assert r.model.get("ptr") == 0

    @_requires_z3
    def test_hex_literal(self):
        r = check_path_feasibility([PathCondition("flags == 0xff", step_index=0)])
        assert r.feasible is True
        assert r.model.get("flags") == 0xFF

    @_requires_z3
    def test_addition_in_condition_sat(self):
        """offset + length <= buffer_size — guard holds when values fit."""
        r = check_path_feasibility([
            PathCondition("offset + length <= buffer_size", step_index=0),
            PathCondition("buffer_size == 64", step_index=1),
            PathCondition("offset > 0", step_index=2),
            PathCondition("length > 0", step_index=3),
        ])
        assert r.feasible is True
        assert r.model.get("buffer_size") == 64

    @_requires_z3
    def test_addition_overflow_path_is_sat(self):
        """Z3 correctly finds an integer overflow path when the guard can be bypassed
        via wraparound — this is the desired behaviour for CWE-190 detection.
        offset(60) + length(very large) overflows, satisfying <= buffer_size(64)."""
        r = check_path_feasibility([
            PathCondition("offset + length <= buffer_size", step_index=0),
            PathCondition("buffer_size == 64", step_index=1),
            PathCondition("offset == 60", step_index=2),
            PathCondition("length > 10", step_index=3),
        ])
        # sat — Z3 finds a wraparound value for length that bypasses the guard
        assert r.feasible is True
        assert r.smt_available is True

    @_requires_z3
    def test_bitmask_alignment(self):
        """rsp & 0xf == 0 — stack alignment check."""
        r = check_path_feasibility([
            PathCondition("rsp & 0xf == 0", step_index=0),
        ])
        assert r.feasible is True

    @_requires_z3
    def test_bitmask_infeasible(self):
        r = check_path_feasibility([
            PathCondition("flags & 0x1 == 0", step_index=0),
            PathCondition("flags & 0x1 == 1", step_index=1),
        ])
        assert r.feasible is False

    @_requires_z3
    def test_multiplication_sat(self):
        """count * 16 < 32768 — Z3 finds a small satisfying count (safe path)."""
        r = check_path_feasibility([
            PathCondition("count * 16 < 32768", step_index=0),
            PathCondition("count > 0", step_index=1),
        ])
        assert r.feasible is True
        assert "count" in r.model
        # 64-bit BV: Z3 finds count <= 2047 (not the 32-bit wraparound path)
        assert r.model["count"] * 16 < 32768

    @_requires_z3
    def test_multiplication_propagates_correctly(self):
        """alloc_size == count * 16 must not silently encode as alloc_size == count."""
        r = check_path_feasibility([
            PathCondition("alloc_size == count * 16", step_index=0),
            PathCondition("count == 4", step_index=1),
        ])
        assert r.feasible is True
        # If * were silently dropped, alloc_size == count → alloc_size == 4.
        # With correct encoding, alloc_size == 4 * 16 == 64.
        assert r.model.get("alloc_size") == 64

    @_requires_z3
    def test_multiplication_makes_path_infeasible(self):
        """count * 4 == 8 AND count == 3 is unsatisfiable (3*4 = 12, not 8)."""
        r = check_path_feasibility([
            PathCondition("count * 4 == 8", step_index=0),
            PathCondition("count == 3", step_index=1),
        ])
        assert r.feasible is False

    @_requires_z3
    def test_bitwise_or_sat(self):
        """flags | 0x1 != 0 — any flags value satisfies this (OR with 1 is always >=1)."""
        r = check_path_feasibility([PathCondition("flags | 0x1 != 0", step_index=0)])
        assert r.feasible is True

    @_requires_z3
    def test_bitwise_or_infeasible(self):
        """flags | 0x1 == 0 — impossible since OR with 1 always sets bit 0."""
        r = check_path_feasibility([PathCondition("flags | 0x1 == 0", step_index=0)])
        assert r.feasible is False

    @_requires_z3
    def test_right_shift_in_lhs_of_comparison(self):
        """n >> 1 < limit — Z3 finds a satisfying n."""
        r = check_path_feasibility([
            PathCondition("n >> 1 < limit", step_index=0),
            PathCondition("limit == 8", step_index=1),
        ])
        assert r.feasible is True
        # n >> 1 < 8 means n < 16; Z3 should give a concrete n
        assert "n" in r.model
        assert r.model["n"] >> 1 < 8

    @_requires_z3
    def test_right_shift_infeasible(self):
        """n >> 1 < 8 AND n >> 1 >= 8 — mutually exclusive."""
        r = check_path_feasibility([
            PathCondition("n >> 1 < 8", step_index=0),
            PathCondition("n >> 1 >= 8", step_index=1),
        ])
        assert r.feasible is False

    @_requires_z3
    def test_left_shift_sat(self):
        """size == n << 3 AND n == 4 — size must be 32."""
        r = check_path_feasibility([
            PathCondition("size == n << 3", step_index=0),
            PathCondition("n == 4", step_index=1),
        ])
        assert r.feasible is True
        assert r.model.get("size") == 32

    @_requires_z3
    def test_shift_in_rhs_of_equality(self):
        """buf_size == count >> 2 — shift on the RHS of ==."""
        r = check_path_feasibility([
            PathCondition("buf_size == count >> 2", step_index=0),
            PathCondition("count == 64", step_index=1),
        ])
        assert r.feasible is True
        assert r.model.get("buf_size") == 16

    @_requires_z3
    def test_trailing_orphan_token_goes_to_unknown(self):
        """Expressions where a token is left unconsumed must go to unknown."""
        r = check_path_feasibility([PathCondition("a b", step_index=0)])
        # 'a b' tokenises to ['a', 'b']; 'b' is orphaned — must be unknown, not encode as 'a'
        assert "a b" in r.unknown


class TestResultStructure:
    """PathSMTResult fields are populated correctly."""

    @_requires_z3
    def test_sat_result_has_empty_unsatisfied(self):
        r = check_path_feasibility([PathCondition("x > 0", step_index=0)])
        assert r.feasible is True
        assert r.unsatisfied == []
        assert r.smt_available is True

    @_requires_z3
    def test_unsat_result_has_empty_model(self):
        r = check_path_feasibility([
            PathCondition("x > 10", step_index=0),
            PathCondition("x < 5", step_index=1),
        ])
        assert r.feasible is False
        assert r.model == {}
        assert r.smt_available is True

    @_requires_z3
    def test_reasoning_string_populated(self):
        r = check_path_feasibility([PathCondition("x == 1", step_index=0)])
        assert isinstance(r.reasoning, str)
        assert len(r.reasoning) > 0

    @_requires_z3
    def test_reasoning_spells_out_profile(self):
        """Reasoning should describe the modelled type in plain text so
        the security researcher reading a validation report doesn't have
        to decode ``bvNN{s,u}`` shorthand."""
        from core.smt_solver import BV_C_INT32
        r_default = check_path_feasibility([PathCondition("x == 1", step_index=0)])
        r_int32 = check_path_feasibility(
            [PathCondition("x == 1", step_index=0)],
            profile=BV_C_INT32,
        )
        assert "64-bit unsigned" in r_default.reasoning
        assert "32-bit signed" in r_int32.reasoning


class TestParametricProfile:
    """Profiles control width, comparison signedness, shift semantics,
    and witness rendering.  The CodeQL testbench's Group 1 cases (CWE-190)
    need BV_C_UINT32 to detect 32-bit wraparound; these tests pin that."""

    @_requires_z3
    def test_default_profile_rejects_32bit_overflow_witness(self):
        """With the realistic upper bound (MAX_RECORDS=0x40000000), 64-bit
        math can't wrap at small counts — the 32-bit-vulnerable range is
        correctly reported infeasible.  The 32-bit variant below proves
        the same conditions DO wrap under BV_C_UINT32."""
        r = check_path_feasibility([
            PathCondition("alloc_size == count * 16", step_index=0),
            PathCondition("alloc_size < 0x8000", step_index=1),
            PathCondition("count > 0x10000000", step_index=2),
            PathCondition("count < 0x40000000", step_index=3),
        ])
        assert r.feasible is False

    @_requires_z3
    def test_uint32_profile_catches_alloc_wraparound(self):
        """ALLOC testbench case: under BV_C_UINT32, Z3 finds the
        wraparound witness where count * 16 overflows modulo 2^32 to a
        small value satisfying alloc_size < MAX_ALLOC."""
        from core.smt_solver import BV_C_UINT32
        r = check_path_feasibility(
            [
                PathCondition("alloc_size == count * 16", step_index=0),
                PathCondition("alloc_size < 0x8000", step_index=1),
                PathCondition("count > 0x10000000", step_index=2),
                PathCondition("count < 0x40000000", step_index=3),
            ],
            profile=BV_C_UINT32,
        )
        assert r.feasible is True
        assert "count" in r.model
        count = r.model["count"]
        assert 0x10000000 < count < 0x40000000
        # alloc_size is count * 16 mod 2^32 (that's the wraparound bug).
        assert r.model.get("alloc_size") == (count * 16) & 0xFFFFFFFF

    @_requires_z3
    def test_int32_profile_right_shift_is_arithmetic(self):
        """BV_C_INT32 (signed) routes '>>' through csem.ashr so the high
        bit propagates.  BV_C_UINT32 uses csem.lshr — zero fill."""
        from core.smt_solver import BV_C_INT32, BV_C_UINT32

        # x = 0x80000000 (32-bit): signed = -2^31, unsigned = 2^31.
        # x >> 1:
        #   signed (ashr)  = 0xC0000000 (= -2^30 = -1073741824)
        #   unsigned (lshr) = 0x40000000 (=  2^30 =  1073741824)
        r_signed = check_path_feasibility(
            [
                PathCondition("x == 0x80000000", step_index=0),
                PathCondition("y == x >> 1", step_index=1),
            ],
            profile=BV_C_INT32,
        )
        assert r_signed.feasible is True
        # Witness renders under signed semantics, so compare the raw bit
        # pattern: `y mod 2^32` should be 0xC0000000 regardless of whether
        # the witness came back as unsigned 3221225472 or signed -1073741824.
        assert (r_signed.model.get("y") % (1 << 32)) == 0xC0000000

        r_unsigned = check_path_feasibility(
            [
                PathCondition("x == 0x80000000", step_index=0),
                PathCondition("y == x >> 1", step_index=1),
            ],
            profile=BV_C_UINT32,
        )
        assert r_unsigned.feasible is True
        assert r_unsigned.model.get("y") == 0x40000000

    @_requires_z3
    def test_ad_hoc_16bit_profile(self):
        """Ad-hoc BVProfile(width=16) works for non-standard widths."""
        from core.smt_solver import BVProfile
        r = check_path_feasibility(
            [PathCondition("x == 0x7FFF", step_index=0)],
            profile=BVProfile(width=16, signed=False),
        )
        assert r.feasible is True
        assert r.model.get("x") == 0x7FFF

    @_requires_z3
    def test_uint32_profile_catches_sum_wraparound(self):
        """SUM testbench case: offset + length <= buffer_size guard is
        bypassable when the unsigned 32-bit sum wraps to a small value."""
        from core.smt_solver import BV_C_UINT32
        r = check_path_feasibility(
            [
                PathCondition("sum == offset + length", step_index=0),
                PathCondition("sum <= buffer_size", step_index=1),
                PathCondition("buffer_size == 64", step_index=2),
                PathCondition("offset > 0x10000", step_index=3),
                PathCondition("length > 0x10000", step_index=4),
            ],
            profile=BV_C_UINT32,
        )
        assert r.feasible is True
        offset, length = r.model["offset"], r.model["length"]
        # The wraparound is the whole point: (offset + length) mod 2^32 ≤ 64.
        assert (offset + length) & 0xFFFFFFFF <= 64
        assert offset > 0x10000 and length > 0x10000

    @_requires_z3
    def test_uint32_profile_catches_mask_wraparound(self):
        """MASK testbench case: base + size <= HEAP_SIZE with wraparound."""
        from core.smt_solver import BV_C_UINT32
        r = check_path_feasibility(
            [
                PathCondition("flags & 0x80000000 == 0", step_index=0),
                PathCondition("size < 4096", step_index=1),
                PathCondition("base + size <= 8192", step_index=2),
                PathCondition("base > 0x80000000", step_index=3),
            ],
            profile=BV_C_UINT32,
        )
        assert r.feasible is True
        base, size = r.model["base"], r.model["size"]
        assert (base + size) & 0xFFFFFFFF <= 8192
        assert base > 0x80000000


class TestStructuredRejection:
    """`unknown_reasons` should classify *why* each unparseable condition
    was dropped, parallel to the textual `unknown` list."""

    def _kind_for(self, result, text):
        for r in result.unknown_reasons:
            if r.text == text:
                return r.kind
        raise AssertionError(
            f"no Rejection for {text!r} in {result.unknown_reasons!r}"
        )

    def test_no_z3_reasons_empty(self):
        """When Z3 is unavailable everything goes to unknown but we
        don't synthesise per-condition rejection reasons — there's no
        parser/solver to assign blame to."""
        with patch("packages.codeql.smt_path_validator._z3_available", return_value=False):
            r = check_path_feasibility([PathCondition("size > 0", step_index=0)])
        assert r.unknown == ["size > 0"]
        assert r.unknown_reasons == []

    @_requires_z3
    def test_parens_rejection(self):
        r = check_path_feasibility([
            PathCondition("validate(ptr, len) == 0", step_index=0),
        ])
        assert self._kind_for(r, "validate(ptr, len) == 0") is RejectionKind.PARENS_NOT_SUPPORTED

    @_requires_z3
    def test_mixed_precedence_rejection(self):
        r = check_path_feasibility([
            PathCondition("a + b * c == 0", step_index=0),
        ])
        assert self._kind_for(r, "a + b * c == 0") is RejectionKind.MIXED_PRECEDENCE

    @_requires_z3
    def test_no_relational_at_top_level_rejection(self):
        """``a b`` has no relational/bitmask top-level shape, so
        :func:`_parse_condition` itself rejects with UNRECOGNIZED_FORM —
        no _parse_expr call ever sees the trailing token."""
        r = check_path_feasibility([PathCondition("a b", step_index=0)])
        assert self._kind_for(r, "a b") is RejectionKind.UNRECOGNIZED_FORM

    @_requires_z3
    def test_trailing_tokens_rejection(self):
        """A trailing operand inside an expression slot — the relational
        top-level matches, then _parse_expr can't consume the dangling
        ``c`` and emits TRAILING_TOKENS."""
        r = check_path_feasibility([PathCondition("a + b c == 0", step_index=0)])
        assert self._kind_for(r, "a + b c == 0") is RejectionKind.TRAILING_TOKENS

    @_requires_z3
    def test_unrecognized_form_rejection(self):
        """A condition without a relational/bitmask top-level pattern."""
        r = check_path_feasibility([PathCondition("size_only", step_index=0)])
        assert self._kind_for(r, "size_only") is RejectionKind.UNRECOGNIZED_FORM

    @_requires_z3
    def test_rejection_carries_hint(self):
        r = check_path_feasibility([
            PathCondition("validate(ptr, len) == 0", step_index=0),
        ])
        rej = next(x for x in r.unknown_reasons if x.text == "validate(ptr, len) == 0")
        assert rej.hint  # non-empty
        assert "synthetic identifier" in rej.hint or "rewrite" in rej.hint.lower()

    @_requires_z3
    def test_rejection_aligned_with_unknown_list(self):
        """For every entry in `unknown`, there's a `unknown_reasons` entry
        with the same text."""
        r = check_path_feasibility([
            PathCondition("size > 0", step_index=0),                    # parses
            PathCondition("validate(p) == 0", step_index=1),            # parens
            PathCondition("a + b * c == 0", step_index=2),              # mixed prec
        ])
        assert set(r.unknown) == {x.text for x in r.unknown_reasons}
