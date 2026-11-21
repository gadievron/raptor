"""Typeless dead-path proofs must not guess variable signedness.

The condition oracle's guards carry no declared types. Over the
unbounded integers ``x > 10 && x < -1`` is unsatisfiable, but for C
``unsigned x`` the ``-1`` converts to the type maximum and the path is
live — so an infeasibility verdict that needs the signed reading of a
negative literal is a guess, not a proof. The mirror holds for large
positive literals: ``x > 0xFFFFFFF0 && x < 5`` is unsat over the
integers, but the hex constant is ``unsigned int`` and drags a signed
``x``'s comparison to the unsigned type, where ``x = -1`` satisfies
both guards. The oracle keeps the refutation only when some variable
is dead under the signed reading, every unsigned re-reading, and every
mixed signed-variable re-reading.
"""

from unittest.mock import patch

from core.audit import condition_smt
from core.audit.condition_extraction import GuardCondition
from core.audit.condition_smt import (
    BoundsConstraint,
    _var_interval_satisfiable,
    _var_interval_satisfiable_mixed,
    check_path_feasibility,
)


def _guard(text: str) -> GuardCondition:
    return GuardCondition(text=text, category="bounds", polarity="required",
                          line=1, resolvable=True, concrete_values={})


def _c(op: str, bound: int, var: str = "x") -> BoundsConstraint:
    return BoundsConstraint(variable=var, operator=op, bound_value=bound)


class TestSignednessAmbiguousDemotion:
    def test_negative_literal_dead_path_is_demoted(self):
        result = check_path_feasibility([_guard("x > 10"), _guard("x < -1")])
        assert result.feasible is None
        assert "signedness-ambiguous" in result.reasoning
        assert result.witness is None

    def test_negative_equality_dead_path_is_demoted(self):
        # unsigned x: ``x == -1`` is ``x == MAX`` — live with ``x > 10``.
        result = check_path_feasibility([_guard("x == -1"), _guard("x > 10")])
        assert result.feasible is None
        assert "signedness-ambiguous" in result.reasoning

    def test_dead_under_both_readings_keeps_refuting(self):
        # unsigned x: ``x < MAX-4 && x > MAX`` is still empty.
        result = check_path_feasibility([_guard("x < -5"), _guard("x > -1")])
        assert result.feasible is False

    def test_nonnegative_contradiction_keeps_refuting(self):
        result = check_path_feasibility([_guard("x > 20"), _guard("x < 10")])
        assert result.feasible is False

    def test_satisfiable_negative_bounds_unaffected(self):
        result = check_path_feasibility([_guard("x > -5"), _guard("x < 5")])
        assert result.feasible is True

    def test_one_robustly_dead_variable_certifies_the_path(self):
        # y is dead under BOTH readings, so the conjunction is dead for
        # every signedness assignment even though x's part is
        # signed-only dead.
        result = check_path_feasibility([
            _guard("x > 10"), _guard("x < -1"),
            _guard("y < -5"), _guard("y > -1"),
        ])
        assert result.feasible is False

    def test_mixed_assignment_liveness_is_respected(self):
        # Uniform all-signed (x dead) and all-unsigned (y dead) readings
        # are both unsat, but x-unsigned with y-signed is live — the
        # per-variable rule must demote.
        result = check_path_feasibility([
            _guard("x > 10"), _guard("x < -1"), _guard("y > -1"),
        ])
        assert result.feasible is None
        assert "signedness-ambiguous" in result.reasoning

    def test_large_hex_literal_dead_path_is_demoted(self):
        # signed x: ``0xFFFFFFF0`` is unsigned int, the comparison goes
        # unsigned and ``x = -1`` re-reads as the type maximum — live.
        result = check_path_feasibility([_guard("x > 0xFFFFFFF0"),
                                         _guard("x < 5")])
        assert result.feasible is None
        assert "signedness-ambiguous" in result.reasoning
        assert result.witness is None

    def test_large_decimal_literal_dead_path_is_demoted(self):
        # Decimal literals stay signed-typed, but the extracted bound
        # is spelling-blind and width-ambiguous (on a 32-bit long the
        # constant turns unsigned long) — same demotion.
        result = check_path_feasibility([_guard("x > 4294967280"),
                                         _guard("x < 5")])
        assert result.feasible is None
        assert "signedness-ambiguous" in result.reasoning

    def test_large_literal_zero_bound_demotes_without_negatives(self):
        # No negative literal anywhere: the old gate never engaged.
        result = check_path_feasibility([_guard("x > 0x80000000"),
                                         _guard("x < 0")])
        assert result.feasible is None
        assert "signedness-ambiguous" in result.reasoning

    def test_beyond_unsigned_range_literal_keeps_refuting(self):
        # Genuinely dead for every C type of x: a 32-bit x compares
        # against ``0x100000000`` in the literal's wider type with its
        # own value (always below 2**32), and for 64-bit x the two
        # guards contradict under both signednesses — the large
        # literal alone must not cost the proof.
        result = check_path_feasibility([_guard("x >= 0x100000000"),
                                         _guard("x < 5")])
        assert result.feasible is False

    def test_demotion_applies_on_the_non_z3_fallback_too(self):
        with patch.object(condition_smt, "_z3_importable",
                          return_value=False):
            result = check_path_feasibility([_guard("x > 10"),
                                             _guard("x < -1")])
        assert result.feasible is None
        assert "signedness-ambiguous" in result.reasoning


class TestVarIntervalSatisfiable:
    def test_half_open_interval_outruns_exclusions(self):
        assert _var_interval_satisfiable(
            [_c(">", 0), _c("!=", 1), _c("!=", 2)], None) is True

    def test_bounded_domain_exhausted_by_exclusions(self):
        cs = [_c(">=", 0), _c("<=", 1), _c("!=", 0), _c("!=", 1)]
        assert _var_interval_satisfiable(cs, None) is False

    def test_unknown_operator_is_unmodeled(self):
        assert _var_interval_satisfiable(
            [BoundsConstraint(variable="x", operator="%", bound_value=2)],
            None) is None

    def test_negative_literal_converts_at_fitting_width(self):
        # width 32: ``x < -1`` reads ``x < 2**32 - 1`` — satisfiable.
        assert _var_interval_satisfiable(
            [_c(">", 10), _c("<", -1)], (1 << 32) - 1) is True

    def test_mixed_reading_finds_the_negative_witness(self):
        # signed-32 x: the first comparison goes unsigned (literal is
        # unsigned int), the second stays signed — x = -1 works.
        assert _var_interval_satisfiable_mixed(
            [_c(">", 0xFFFFFFF0), _c("<", 5)], 32) is True

    def test_mixed_reading_keeps_true_contradictions(self):
        assert _var_interval_satisfiable_mixed(
            [_c(">", 20), _c("<", 10)], 32) is False

    def test_mixed_reading_unknown_operator_is_unmodeled(self):
        assert _var_interval_satisfiable_mixed(
            [BoundsConstraint(variable="x", operator="%", bound_value=2)],
            32) is None

    def test_wider_rank_negative_literal_keeps_its_value(self):
        # A literal below -2**32 cannot convert to a 32-bit unsigned
        # type; the comparison happens in the literal's wider signed
        # type, where a nonnegative x is never below it.
        assert _var_interval_satisfiable(
            [_c("<", -(1 << 40))], (1 << 32) - 1) is False
        # At 64 bits the same literal fits and converts — satisfiable.
        assert _var_interval_satisfiable(
            [_c("<", -(1 << 40))], (1 << 64) - 1) is True
