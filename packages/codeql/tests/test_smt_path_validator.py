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
        """Conditions outside the supported grammar go to unknown, not crash.

        Operators silently dropped by the tokeniser (``~``, ``^``, ``/``,
        ``%``, ...) are caught by the consumed-input check and rejected
        rather than mis-encoded.
        """
        r = check_path_feasibility([
            PathCondition("size > 0", step_index=0),
            PathCondition("~mask == 0xFFFFFFFF", step_index=1),
        ])
        assert "~mask == 0xFFFFFFFF" in r.unknown
        # The parseable condition still runs; result is sat or None, not outright infeasible
        assert r.feasible is not False

    @_requires_z3
    def test_all_unknown_returns_none(self):
        """If nothing is parseable, feasible must be None (not True)."""
        r = check_path_feasibility([
            PathCondition("~mask == 0", step_index=0),  # NOT silently dropped
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
    def test_unbalanced_paren_kind(self):
        """Unbalanced parens (extra ``(`` or ``)``) reject with
        UNBALANCED_PARENS — the dedicated kind, not the deprecated
        PARENS_NOT_SUPPORTED.  Balanced grouping parens parse via
        precedence climbing and don't reach this rejection path."""
        r = check_path_feasibility([
            PathCondition("(a + b > 0", step_index=0),
        ])
        assert self._kind_for(r, "(a + b > 0") is RejectionKind.UNBALANCED_PARENS

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
        # Top-level shape that doesn't match any relational/bitmask form
        # comes back with UNRECOGNIZED_FORM and a hint pointing at the
        # accepted templates.
        r = check_path_feasibility([
            PathCondition("size_only", step_index=0),
        ])
        rej = next(x for x in r.unknown_reasons if x.text == "size_only")
        assert rej.hint  # non-empty
        assert "lhs" in rej.hint.lower()

    @_requires_z3
    def test_rejection_aligned_with_unknown_list(self):
        """For every entry in `unknown`, there's a `unknown_reasons` entry
        with the same text."""
        r = check_path_feasibility([
            PathCondition("size > 0", step_index=0),                    # parses
            PathCondition("~mask == 0", step_index=1),                  # NOT silently dropped
            PathCondition("a / b > 0", step_index=2),                   # division silently dropped
        ])
        assert set(r.unknown) == {x.text for x in r.unknown_reasons}


# ---------------------------------------------------------------------------
# Free-variable fallback for function-call subterms
# ---------------------------------------------------------------------------

class TestFreeVariableFallback:
    """``ident(...)`` subterms are replaced with fresh free variables so
    the rest of the condition can drive feasibility analysis instead of
    the whole condition being dropped to unknown.
    """

    @_requires_z3
    def test_simple_call_lhs(self):
        """``strlen(input) < 1024`` parses via the fallback."""
        r = check_path_feasibility([
            PathCondition("strlen(input) < 1024", step_index=0),
        ])
        assert r.unknown == []
        assert r.feasible is True

    @_requires_z3
    def test_simple_call_rhs(self):
        """Calls work in RHS position too: ``0 < strlen(input)``."""
        r = check_path_feasibility([
            PathCondition("0 < strlen(input)", step_index=0),
        ])
        assert r.unknown == []
        assert r.feasible is True

    @_requires_z3
    def test_zero_arg_call(self):
        """Zero-arg calls (``getpid()``) parse identically."""
        r = check_path_feasibility([
            PathCondition("getpid() != 0", step_index=0),
        ])
        assert r.unknown == []
        assert r.feasible is True

    @_requires_z3
    def test_multi_arg_call(self):
        """Calls with internal commas/operators don't confuse the parser."""
        r = check_path_feasibility([
            PathCondition("min(a, b) > 0", step_index=0),
        ])
        assert r.unknown == []
        assert r.feasible is True

    @_requires_z3
    def test_nested_call_collapses(self):
        """Nested calls collapse to a single placeholder via the
        balanced-paren walk — outer call drives the substitution."""
        r = check_path_feasibility([
            PathCondition("f(g(x), h(y)) < 100", step_index=0),
        ])
        assert r.unknown == []
        assert r.feasible is True

    @_requires_z3
    def test_two_calls_distinct_free_vars(self):
        """Two textually-identical calls produce *distinct* placeholders.

        Calls aren't assumed pure, so ``strlen(s) == strlen(s)`` is
        satisfiable — but ``strlen(s) != strlen(s)`` is also satisfiable
        (different anon vars).  This is the conservative stance: the
        solver never claims infeasibility from elided subterms.
        """
        sat_eq = check_path_feasibility([
            PathCondition("strlen(s) == strlen(s)", step_index=0),
        ])
        sat_ne = check_path_feasibility([
            PathCondition("strlen(s) != strlen(s)", step_index=0),
        ])
        assert sat_eq.feasible is True
        assert sat_ne.feasible is True

    @_requires_z3
    def test_call_in_bitmask_lhs(self):
        """Function call in bitmask LHS: ``strlen(s) & 0xff == 0``."""
        r = check_path_feasibility([
            PathCondition("strlen(s) & 0xff == 0", step_index=0),
        ])
        assert r.unknown == []
        assert r.feasible is True

    @_requires_z3
    def test_call_does_not_constrain_path(self):
        """Conditions reduced to ``anon OP literal`` mustn't force
        infeasibility on otherwise-compatible peer conditions."""
        r = check_path_feasibility([
            PathCondition("size > 0", step_index=0),
            PathCondition("strlen(input) < 1024", step_index=1),
        ])
        assert r.unknown == []
        assert r.feasible is True

    @_requires_z3
    @pytest.mark.parametrize("expr", [
        "strlen(input < 1024",  # missing close, mid-expression
        "strlen(x",             # missing close, at EOI
        "strlen(x))",           # extra close from the right
        "f(g(x)",               # nested with one missing close
        "strlen x)",            # orphan close, no preceding (
    ])
    def test_unbalanced_parens_still_rejected(self, expr):
        """Any paren imbalance — open without close, close without open,
        or nested mismatch — falls through the substitution and is
        rejected by the balance check (or the expression parser) rather
        than silently masquerading as a parsed call."""
        r = check_path_feasibility([PathCondition(expr, step_index=0)])
        assert expr in r.unknown
        rej = next(x for x in r.unknown_reasons if x.text == expr)
        assert rej.kind is RejectionKind.UNBALANCED_PARENS

    @_requires_z3
    def test_fallback_preserves_real_constraints(self):
        """A path with a parsed real constraint and a fallback-recovered
        call must still detect infeasibility driven by the real constraint."""
        r = check_path_feasibility([
            PathCondition("size > 100", step_index=0),
            PathCondition("size < 50", step_index=1),
            PathCondition("strlen(input) < 1024", step_index=2),  # free var
        ])
        # The two `size` constraints are mutually exclusive regardless of
        # the free-var-only third condition.
        assert r.feasible is False

    @_requires_z3
    def test_call_with_complex_inner(self):
        """Inner expressions inside the call (operators, nested calls,
        whitespace) don't matter — the whole balanced span becomes one
        placeholder."""
        r = check_path_feasibility([
            PathCondition("compute(a + b * c, lookup(table, key)) > 0", step_index=0),
        ])
        assert r.unknown == []
        assert r.feasible is True

    @_requires_z3
    def test_anon_counter_progresses_across_conditions(self):
        """Free-var allocator is seeded from existing ``vars_`` so
        anon names don't collide across conditions in one path."""
        # If both calls were assigned `_anon_0`, they'd share a Z3
        # variable and 'first != 0 AND second == 0' would be unsat-ish
        # in some encodings.  With distinct vars, both are satisfiable.
        r = check_path_feasibility([
            PathCondition("first(x) != 0", step_index=0),
            PathCondition("second(y) == 0", step_index=1),
        ])
        assert r.unknown == []
        assert r.feasible is True


# ---------------------------------------------------------------------------
# C operator precedence
# ---------------------------------------------------------------------------

class TestPrecedence:
    """C precedence: ``*`` > ``+ -`` > ``<< >>`` > ``|``, all left-associative.

    The previous parser was strict left-to-right and rejected mixed-class
    expressions with MIXED_PRECEDENCE.  The current parser binds operators
    by C precedence, so mixed expressions encode with the grouping a C
    compiler would produce.  These tests pin that grouping by asserting
    the *value* a model would have under the correct interpretation.
    """

    @_requires_z3
    def test_multiplication_binds_tighter_than_addition_rhs(self):
        """``a + b * c == 64`` with ``a=4, b=4, c=15`` is feasible iff
        the parse is ``a + (b * c) = 4 + 60 = 64``.  An LTR parse would
        compute ``(a + b) * c = 8 * 15 = 120`` — infeasible."""
        r = check_path_feasibility([
            PathCondition("a + b * c == 64", step_index=0),
            PathCondition("a == 4", step_index=1),
            PathCondition("b == 4", step_index=2),
            PathCondition("c == 15", step_index=3),
        ])
        assert r.feasible is True

    @_requires_z3
    def test_multiplication_binds_tighter_than_addition_lhs(self):
        """``a * b + c == 19`` with ``a=2, b=8, c=3`` requires ``(a*b)+c``."""
        r = check_path_feasibility([
            PathCondition("a * b + c == 19", step_index=0),
            PathCondition("a == 2", step_index=1),
            PathCondition("b == 8", step_index=2),
            PathCondition("c == 3", step_index=3),
        ])
        assert r.feasible is True

    @_requires_z3
    def test_subtraction_left_associative(self):
        """``a - b - c`` parses as ``(a - b) - c``.  With a=10, b=3, c=2:
        ``(10-3)-2 = 5``, not ``10-(3-2) = 9``."""
        r = check_path_feasibility([
            PathCondition("a - b - c == 5", step_index=0),
            PathCondition("a == 10", step_index=1),
            PathCondition("b == 3", step_index=2),
            PathCondition("c == 2", step_index=3),
        ])
        assert r.feasible is True

    @_requires_z3
    def test_shift_lower_precedence_than_addition(self):
        """C surprise: ``a + b << 2`` is ``(a + b) << 2``, not
        ``a + (b << 2)``.  With a=1, b=3: ``(1+3) << 2 = 16``, not
        ``1 + (3 << 2) = 13``."""
        r = check_path_feasibility([
            PathCondition("a + b << 2 == 16", step_index=0),
            PathCondition("a == 1", step_index=1),
            PathCondition("b == 3", step_index=2),
        ])
        assert r.feasible is True

    @_requires_z3
    def test_or_lowest_precedence(self):
        """``a | b + c`` is ``a | (b + c)``.  Pick values that distinguish
        the two readings: a=2, b=1, c=2 gives 2|(1+2)=2|3=3, while the
        LTR misparse (2|1)+2 = 3+2 = 5."""
        r = check_path_feasibility([
            PathCondition("a | b + c == 3", step_index=0),
            PathCondition("a == 2", step_index=1),
            PathCondition("b == 1", step_index=2),
            PathCondition("c == 2", step_index=3),
        ])
        assert r.feasible is True

    @_requires_z3
    def test_multiplication_binds_tighter_than_shift(self):
        """``a + b * c << d`` is C-parsed as ``(a + (b * c)) << d``.
        a=1, b=2, c=3, d=1: ``(1 + 6) << 1 = 14``.  If shift bound
        tighter than mul: ``a + b * (c << d) = 1 + 2*6 = 13``."""
        r = check_path_feasibility([
            PathCondition("a + b * c << d == 14", step_index=0),
            PathCondition("a == 1", step_index=1),
            PathCondition("b == 2", step_index=2),
            PathCondition("c == 3", step_index=3),
            PathCondition("d == 1", step_index=4),
        ])
        assert r.feasible is True

    @_requires_z3
    def test_three_level_mix(self):
        """``a | b + c * d`` is ``a | (b + (c * d))``.  Values:
        a=0x10, b=2, c=3, d=4 → 0x10 | (2 + 12) = 0x10 | 14 = 0x1E."""
        r = check_path_feasibility([
            PathCondition("a | b + c * d == 0x1E", step_index=0),
            PathCondition("a == 0x10", step_index=1),
            PathCondition("b == 2", step_index=2),
            PathCondition("c == 3", step_index=3),
            PathCondition("d == 4", step_index=4),
        ])
        assert r.feasible is True


# ---------------------------------------------------------------------------
# Parenthesised grouping
# ---------------------------------------------------------------------------

class TestParensGrouping:
    """Balanced parens override C precedence and are now accepted by the
    expression parser.  Function-call shapes (``ident(...)``) still go
    through the free-variable fallback first; only the leftover ``( ... )``
    is grouping."""

    @_requires_z3
    def test_parens_override_precedence(self):
        """``(a + b) * c == 30`` with a=2, b=3, c=6: ``(2+3)*6 = 30``.
        Without the parens, the C reading is ``a + (b * c) = 2 + 18 = 20``."""
        r = check_path_feasibility([
            PathCondition("(a + b) * c == 30", step_index=0),
            PathCondition("a == 2", step_index=1),
            PathCondition("b == 3", step_index=2),
            PathCondition("c == 6", step_index=3),
        ])
        assert r.feasible is True

    @_requires_z3
    def test_parens_force_shift_then_add(self):
        """``a + (b << 2) == 13`` with a=1, b=3: ``1 + (3<<2) = 13``.
        Without the parens, the C reading is ``(a+b) << 2 = 16``."""
        r = check_path_feasibility([
            PathCondition("a + (b << 2) == 13", step_index=0),
            PathCondition("a == 1", step_index=1),
            PathCondition("b == 3", step_index=2),
        ])
        assert r.feasible is True

    @_requires_z3
    def test_nested_parens(self):
        """``((x))`` parses as ``x`` — extra outer layers are no-ops."""
        r = check_path_feasibility([
            PathCondition("((x)) == 42", step_index=0),
        ])
        assert r.feasible is True
        assert r.model.get("x") == 42

    @_requires_z3
    def test_deeply_nested_parens(self):
        r = check_path_feasibility([
            PathCondition("(((y))) > 0", step_index=0),
            PathCondition("y < 100", step_index=1),
        ])
        assert r.feasible is True
        assert 0 < r.model["y"] < 100

    @_requires_z3
    def test_parens_on_both_sides(self):
        """Relational regex must split at the operator with parens on
        either side.  ``(a + b) == (c + d)`` — both sides parse."""
        r = check_path_feasibility([
            PathCondition("(a + b) == (c + d)", step_index=0),
            PathCondition("a == 1", step_index=1),
            PathCondition("b == 2", step_index=2),
            PathCondition("c == 0", step_index=3),
        ])
        assert r.feasible is True
        assert r.model.get("d") == 3

    @_requires_z3
    def test_parens_in_bitmask_lhs(self):
        """Bitmask form's LHS goes through ``_parse_expr``; parens work
        there too: ``(a + b) & 0xff == 0``."""
        r = check_path_feasibility([
            PathCondition("(a + b) & 0xff == 0", step_index=0),
        ])
        assert r.feasible is True

    @_requires_z3
    def test_unmatched_open_paren_in_expression(self):
        """``(a + b > 0`` — relational splits at ``>``, LHS=``(a + b ``
        has unmatched ``(``.  The early balance check catches this."""
        r = check_path_feasibility([
            PathCondition("(a + b > 0", step_index=0),
        ])
        assert "(a + b > 0" in r.unknown
        rej = next(x for x in r.unknown_reasons if x.text == "(a + b > 0")
        assert rej.kind is RejectionKind.UNBALANCED_PARENS

    @_requires_z3
    def test_unmatched_close_paren_in_expression(self):
        """``a + b) > 0`` — extra ``)``."""
        r = check_path_feasibility([
            PathCondition("a + b) > 0", step_index=0),
        ])
        assert "a + b) > 0" in r.unknown
        rej = next(x for x in r.unknown_reasons if x.text == "a + b) > 0")
        assert rej.kind is RejectionKind.UNBALANCED_PARENS

    @_requires_z3
    def test_swapped_parens(self):
        """``)a + b( > 0`` — balanced count but the structure is wrong.
        The early balance check sees ``)`` first and rejects before
        ``_parse_expr`` runs."""
        r = check_path_feasibility([
            PathCondition(")a + b( > 0", step_index=0),
        ])
        assert ")a + b( > 0" in r.unknown
        rej = next(x for x in r.unknown_reasons if x.text == ")a + b( > 0")
        assert rej.kind is RejectionKind.UNBALANCED_PARENS

    @_requires_z3
    def test_empty_parens_in_expression(self):
        """``() + 1 > 0`` — ``()`` has no operand inside."""
        r = check_path_feasibility([
            PathCondition("() + 1 > 0", step_index=0),
        ])
        assert "() + 1 > 0" in r.unknown

    @_requires_z3
    def test_relational_inside_parens_rejected(self):
        """``(a == b) + 1 > 0`` — the relational regex splits at the first
        ``==`` (inside the parens), so ``_parse_expr`` sees ``(a`` as the
        LHS — unbalanced.  The condition goes to unknown regardless of the
        specific rejection kind, which is the correct outcome."""
        r = check_path_feasibility([
            PathCondition("(a == b) + 1 > 0", step_index=0),
        ])
        assert "(a == b) + 1 > 0" in r.unknown

    @_requires_z3
    def test_relational_inside_rhs_parens_gives_unsupported_operator(self):
        """``result == (a > b) + 1`` — the relational regex splits at
        ``==``, giving ``_parse_expr`` the RHS text ``(a > b) + 1``.
        Inside the paren group, ``>`` is a condition-level operator that
        can't appear in an arithmetic subexpression.  Must reject with
        UNSUPPORTED_OPERATOR, not UNBALANCED_PARENS."""
        r = check_path_feasibility([
            PathCondition("result == (a > b) + 1", step_index=0),
        ])
        assert "result == (a > b) + 1" in r.unknown
        rej = next(x for x in r.unknown_reasons if x.text == "result == (a > b) + 1")
        assert rej.kind is RejectionKind.UNSUPPORTED_OPERATOR

    @_requires_z3
    def test_deeply_nested_parens_within_limit(self):
        """32-deep nesting is well within the 64-level cap."""
        inner = "x"
        for _ in range(32):
            inner = f"({inner})"
        r = check_path_feasibility([
            PathCondition(f"{inner} == 42", step_index=0),
        ])
        assert r.feasible is True
        assert r.model.get("x") == 42

    @_requires_z3
    def test_parens_exceeding_depth_limit_rejected(self):
        """Nesting beyond _MAX_PAREN_DEPTH (64) is rejected to prevent
        unbounded recursion from untrusted input."""
        from packages.codeql.smt_path_validator import _MAX_PAREN_DEPTH
        inner = "x"
        for _ in range(_MAX_PAREN_DEPTH + 1):
            inner = f"({inner})"
        r = check_path_feasibility([
            PathCondition(f"{inner} > 0", step_index=0),
        ])
        assert f"{inner} > 0" in r.unknown
        rej = next(x for x in r.unknown_reasons if x.text == f"{inner} > 0")
        assert rej.kind is RejectionKind.UNRECOGNIZED_FORM
        assert "depth" in rej.detail


# ---------------------------------------------------------------------------
# check_path_feasibility — input hardening caps
# ---------------------------------------------------------------------------

class TestInputLimits:
    """Pre-parse caps on input size and call shape (C4 parser hardening).

    These caps defend the parser against pathological inputs without
    relying on Z3's per-call timeout — they fire before any solver work
    runs, so even a malformed extraction or amplification attack costs
    only the cap-check, not parser walk + Z3 round-trip.
    """

    @_requires_z3
    def test_condition_length_within_cap_accepted(self):
        """A condition just under ``_MAX_CONDITION_CHARS`` parses normally."""
        from packages.codeql.smt_path_validator import _MAX_CONDITION_CHARS
        # Build a condition of length _MAX_CONDITION_CHARS that the parser
        # accepts: ``x + x + x + ... > 0``.  Each ``x + `` token is 4 chars.
        prefix = "x + " * ((_MAX_CONDITION_CHARS - len("x > 0")) // 4)
        cond = prefix + "x > 0"
        assert len(cond) <= _MAX_CONDITION_CHARS
        r = check_path_feasibility([PathCondition(cond, step_index=0)])
        # Either feasible or rejected for non-length reasons — must NOT
        # carry INPUT_TOO_LONG.
        kinds = {rej.kind for rej in r.unknown_reasons}
        assert RejectionKind.INPUT_TOO_LONG not in kinds

    @_requires_z3
    def test_condition_length_over_cap_rejected(self):
        """A condition exceeding ``_MAX_CONDITION_CHARS`` is rejected with
        ``INPUT_TOO_LONG`` before any parser work runs."""
        from packages.codeql.smt_path_validator import _MAX_CONDITION_CHARS
        huge = "x" + ("=" * _MAX_CONDITION_CHARS) + "y"
        assert len(huge) > _MAX_CONDITION_CHARS
        r = check_path_feasibility([PathCondition(huge, step_index=0)])
        assert huge in r.unknown
        rej = next(x for x in r.unknown_reasons if x.text == huge)
        assert rej.kind is RejectionKind.INPUT_TOO_LONG
        # Detail mentions the observed length and the cap.
        assert str(len(huge)) in rej.detail
        assert str(_MAX_CONDITION_CHARS) in rej.detail
        # Hint guides the caller to a fix.
        assert "shorten" in rej.hint or "split" in rej.hint

    @_requires_z3
    def test_condition_count_within_cap_accepted(self):
        """A call with ``_MAX_CONDITIONS_PER_CALL`` items runs normally."""
        from packages.codeql.smt_path_validator import _MAX_CONDITIONS_PER_CALL
        # Use distinct variable names per condition so they trivially
        # satisfy together — focus the test on the count check, not on
        # condition semantics.
        conds = [
            PathCondition(f"x{i} > 0", step_index=i)
            for i in range(_MAX_CONDITIONS_PER_CALL)
        ]
        r = check_path_feasibility(conds)
        # Either feasible or rejected for non-count reasons — must NOT
        # carry TOO_MANY_CONDITIONS.
        kinds = {rej.kind for rej in r.unknown_reasons}
        assert RejectionKind.TOO_MANY_CONDITIONS not in kinds

    @_requires_z3
    def test_condition_count_over_cap_refused(self):
        """A call with more than ``_MAX_CONDITIONS_PER_CALL`` items refuses
        the whole call with ``feasible=None`` and a single
        ``TOO_MANY_CONDITIONS`` rejection."""
        from packages.codeql.smt_path_validator import _MAX_CONDITIONS_PER_CALL
        n = _MAX_CONDITIONS_PER_CALL + 1
        conds = [
            PathCondition(f"x{i} > 0", step_index=i) for i in range(n)
        ]
        r = check_path_feasibility(conds)
        # Whole call refused — no partial verdict.
        assert r.feasible is None
        # Every input condition is in unknown (caller can match them back).
        assert len(r.unknown) == n
        # Exactly one TOO_MANY_CONDITIONS rejection — not one per condition,
        # because the cap is a call-shape issue, not a per-condition issue.
        too_many = [
            rej for rej in r.unknown_reasons
            if rej.kind is RejectionKind.TOO_MANY_CONDITIONS
        ]
        assert len(too_many) == 1
        rej = too_many[0]
        assert str(n) in rej.detail
        assert str(_MAX_CONDITIONS_PER_CALL) in rej.detail
        # Reasoning surfaces the cap so log readers understand the refusal.
        assert "refused" in r.reasoning.lower()
        assert str(_MAX_CONDITIONS_PER_CALL) in r.reasoning

    @_requires_z3
    def test_length_cap_fires_before_paren_depth(self):
        """When BOTH limits would fire, INPUT_TOO_LONG should reach the
        caller first — the length check runs at the very top of
        _parse_condition, before any structural inspection.

        This matters because the length check is cheap (one comparison)
        while paren-depth detection runs the early-balance scan over the
        whole input.  An adversarial input that's both very long AND has
        deep nesting must short-circuit on length so the balance scan
        never executes."""
        from packages.codeql.smt_path_validator import (
            _MAX_CONDITION_CHARS, _MAX_PAREN_DEPTH,
        )
        # Build a string that's BOTH over the char cap AND has deeper
        # nesting than _MAX_PAREN_DEPTH.
        inner = "x"
        for _ in range(_MAX_PAREN_DEPTH + 1):
            inner = f"({inner})"
        # Pad with extra chars to exceed the char cap.
        pad = "z" * (_MAX_CONDITION_CHARS + 10)
        cond = f"{inner} == {pad}"
        assert len(cond) > _MAX_CONDITION_CHARS
        r = check_path_feasibility([PathCondition(cond, step_index=0)])
        rej = next(x for x in r.unknown_reasons if x.text == cond)
        # Length cap fires first.
        assert rej.kind is RejectionKind.INPUT_TOO_LONG

    @_requires_z3
    def test_oversize_condition_among_normal_ones(self):
        """One oversize condition is rejected without poisoning the rest
        of the call — the other conditions still parse and contribute to
        the joint feasibility verdict."""
        from packages.codeql.smt_path_validator import _MAX_CONDITION_CHARS
        huge = "y" + ("=" * _MAX_CONDITION_CHARS) + "0"
        r = check_path_feasibility([
            PathCondition("x > 0", step_index=0),
            PathCondition(huge, step_index=1),
            PathCondition("x < 100", step_index=2),
        ])
        # The two well-formed conditions are jointly satisfiable.
        assert r.feasible is True
        # The oversize one is rejected with INPUT_TOO_LONG.
        assert huge in r.unknown
        rej = next(x for x in r.unknown_reasons if x.text == huge)
        assert rej.kind is RejectionKind.INPUT_TOO_LONG


# ---------------------------------------------------------------------------
# check_path_feasibility — prefer_witness (Z3 Optimize integration)
# ---------------------------------------------------------------------------

class TestPreferWitness:
    """Driving the witness toward extreme values via z3.Optimize.

    Without ``prefer_witness`` Z3 returns the smallest model that
    satisfies the conditions — typically the trivial ``x=0``
    assignment.  With ``prefer_witness=("var", "max")`` (or ``"min"``)
    the encoder swaps in ``z3.Optimize`` and adds a maximize / minimize
    objective on the named variable, producing an *exploit*-shape
    witness instead.
    """

    def _cwe190_conds(self):
        # Canonical CWE-190 32-bit wraparound shape.  Without a witness
        # hint Z3 returns ``count=0``; with ``max:count`` it lands in
        # the wraparound region (count * 16 > 2^32 - 1).
        return [
            PathCondition("alloc_size == count * 16", step_index=0),
            PathCondition("alloc_size < 0x8000", step_index=1),
        ]

    @_requires_z3
    def test_default_returns_trivial_witness(self):
        """Sanity baseline: without prefer_witness, CWE-190 conditions
        produce the trivial count=0 witness."""
        from core.smt_solver import BV_C_UINT32
        r = check_path_feasibility(
            self._cwe190_conds(), profile=BV_C_UINT32,
        )
        assert r.feasible is True
        assert r.model.get("count") == 0

    @_requires_z3
    def test_max_drives_witness_into_wraparound_region(self):
        """``max:count`` produces a witness where count * 16 exceeds
        2^32 — confirming Z3 found a wraparound assignment."""
        from core.smt_solver import BV_C_UINT32
        r = check_path_feasibility(
            self._cwe190_conds(), profile=BV_C_UINT32,
            prefer_witness=("count", "max"),
        )
        assert r.feasible is True
        count = r.model.get("count")
        assert count is not None and count > 0, (
            f"prefer_witness max:count should produce non-trivial count, got {count}"
        )
        # On uint32, count * 16 in C semantics wraps; the test confirms
        # the witness lands in a region where unwrapped multiplication
        # would exceed UINT32_MAX.
        assert count * 16 > 0xFFFFFFFF, (
            f"witness count={count} does not lie in the wraparound region"
        )

    @_requires_z3
    def test_min_drives_witness_to_floor(self):
        """``min:count`` with a lower-bound condition returns the
        smallest count above the bound."""
        from core.smt_solver import BV_C_UINT32
        r = check_path_feasibility(
            self._cwe190_conds() + [PathCondition("count > 1000", step_index=2)],
            profile=BV_C_UINT32,
            prefer_witness=("count", "min"),
        )
        assert r.feasible is True
        # min above the floor of 1000 → 1001.
        assert r.model.get("count") == 1001

    @_requires_z3
    def test_absent_variable_silent_skip(self):
        """When the named variable doesn't appear in any condition the
        objective is silently dropped and the witness reverts to the
        default smallest-model behaviour.  No error — Z3 still returns
        a valid (non-extremal) witness."""
        from core.smt_solver import BV_C_UINT32
        r = check_path_feasibility(
            self._cwe190_conds(), profile=BV_C_UINT32,
            prefer_witness=("bogusvar", "max"),
        )
        assert r.feasible is True
        # Default trivial witness comes back (count=0); no exception
        # raised for the missing variable.
        assert r.model.get("count") == 0
        assert "bogusvar" not in r.model

    @_requires_z3
    def test_unsat_still_unsat_in_witness_mode(self):
        """An unsat path remains unsat regardless of witness direction
        — the objective only affects which sat witness is chosen, not
        whether one exists.  unsat-core info must still surface."""
        from core.smt_solver import BV_C_UINT32
        r = check_path_feasibility(
            [PathCondition("x > 100", step_index=0),
             PathCondition("x < 50", step_index=1)],
            profile=BV_C_UINT32,
            prefer_witness=("x", "max"),
        )
        assert r.feasible is False
        # unsat-core info preserved across the Solver→Optimize swap.
        assert "x > 100" in r.unsatisfied
        assert "x < 50" in r.unsatisfied

    @_requires_z3
    def test_witness_mode_compatible_with_timeout(self):
        """``timeout_ms`` is honoured by the Optimize backend the same
        way it is by Solver — empty pending list short-circuits to
        ``feasible=True`` without solver work, but the timeout config
        threads through cleanly."""
        from core.smt_solver import BV_C_UINT32
        r = check_path_feasibility(
            self._cwe190_conds(), profile=BV_C_UINT32,
            prefer_witness=("count", "max"),
            timeout_ms=10000,
        )
        assert r.feasible is True
        assert r.model.get("count") is not None
