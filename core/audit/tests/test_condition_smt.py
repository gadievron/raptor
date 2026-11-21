"""Tests for condition_smt — constant-to-SMT bridge for guard sufficiency."""


import pytest

pytestmark = pytest.mark.usefixtures("owned_smt_subprocess")

from core.audit.condition_extraction import GuardCondition, SinkGuard
from core.audit.condition_smt import (
    _SECURITY_FIELDS,
    _extract_lock_object,
    check_all_sufficiency,
    check_early_release,
    check_guard_sufficiency,
    check_lock_discipline,
    check_lock_domain,
    check_off_by_one,
    check_path_feasibility,
    check_signed_mismatch,
    constraints_for_guard,
    extract_bounds_constraints,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _guard(text: str, category: str = "bounds", **kw) -> GuardCondition:
    return GuardCondition(
        text=text, category=category, polarity="required", line=1, **kw
    )


def _sg(
    sink_api: str,
    guards: list,
    line: int = 10,
    sink_args: list[str] | None = None,
) -> SinkGuard:
    return SinkGuard(
        sink_file="test.c",
        sink_line=line,
        sink_function="process",
        sink_api=sink_api,
        guards=guards,
        unconditional=(len(guards) == 0),
        sink_args=sink_args if sink_args is not None else [],
    )


# ---------------------------------------------------------------------------
# Bounds constraint extraction tests
# ---------------------------------------------------------------------------


class TestExtractBoundsConstraints:
    def test_simple_less_than(self):
        g = _guard("len < 1024", resolvable=True, concrete_values={"MAX_SIZE": "1024"})
        constraints = extract_bounds_constraints(g)
        assert len(constraints) >= 1
        found = [c for c in constraints if c.variable == "len"]
        assert found
        assert found[0].operator == "<"
        assert found[0].bound_value == 1024

    def test_less_equal(self):
        g = _guard("n <= 256", resolvable=True, concrete_values={})
        constraints = extract_bounds_constraints(g)
        found = [c for c in constraints if c.variable == "n"]
        assert found
        assert found[0].operator == "<="
        assert found[0].bound_value == 256

    def test_greater_than(self):
        g = _guard("size > 0", resolvable=True, concrete_values={})
        constraints = extract_bounds_constraints(g)
        found = [c for c in constraints if c.variable == "size"]
        assert found
        assert found[0].operator == ">"
        assert found[0].bound_value == 0

    def test_hex_value(self):
        g = _guard("offset < 0x1000", resolvable=True, concrete_values={})
        constraints = extract_bounds_constraints(g)
        found = [c for c in constraints if c.variable == "offset"]
        assert found
        assert found[0].bound_value == 4096

    def test_constant_resolution(self):
        g = _guard(
            "len < MAX_BUF",
            resolvable=True,
            concrete_values={"MAX_BUF": "4096"},
        )
        constraints = extract_bounds_constraints(g)
        found = [c for c in constraints if c.variable == "len"]
        assert found
        assert found[0].bound_value == 4096

    def test_reversed_comparison(self):
        g = _guard("256 >= count", resolvable=True, concrete_values={})
        constraints = extract_bounds_constraints(g)
        found = [c for c in constraints if c.variable == "count"]
        assert found
        assert found[0].operator == "<="
        assert found[0].bound_value == 256

    def test_no_numeric_value(self):
        g = _guard("len < other_var", resolvable=False, concrete_values={})
        constraints = extract_bounds_constraints(g)
        # other_var is not numeric, so no constraint extracted
        assert len(constraints) == 0

    def test_not_resolvable_still_extracts_literals(self):
        g = _guard("x < 100", resolvable=True, concrete_values={})
        constraints = extract_bounds_constraints(g)
        assert len(constraints) >= 1


# ---------------------------------------------------------------------------
# SMT sufficiency tests (arithmetic fallback — Z3 may not be available)
# ---------------------------------------------------------------------------


class TestCheckGuardSufficiency:
    def test_guard_insufficient_for_buffer(self):
        g = _guard(
            "len < MAX_SIZE",
            resolvable=True,
            concrete_values={"MAX_SIZE": "4096"},
        )
        sg = _sg("memcpy", [g])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        # Guard allows up to 4095, buffer is 256 → insufficient
        r = results[0]
        assert r.feasible is True  # overflow IS feasible
        assert r.guard_sufficient is False

    def test_guard_sufficient_for_buffer(self):
        # Soundness: an upper bound alone is NOT sufficient — a signed
        # len = -1 passes ``len < 128`` and wraps to SIZE_MAX at the
        # sink.  Sufficiency requires a non-negative lower bound too.
        g = _guard(
            "len >= 0 && len < BUF_SIZE",
            resolvable=True,
            concrete_values={"BUF_SIZE": "128"},
        )
        # Sufficiency proofs additionally require the size-argument
        # binding: the guarded variable must be what the sink copies.
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "len"])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        r = results[0]
        assert r.feasible is False  # overflow NOT feasible
        assert r.guard_sufficient is True

    def test_upper_bound_alone_not_sufficient_signed_wrap(self):
        # Regression: the old z3.Int model had no wrap, so
        # ``len < 1024`` with a 4096-byte buffer came back 'guard
        # sufficient' while len = -1 reaches memcpy as SIZE_MAX.
        g = _guard(
            "len < MAXSZ",
            resolvable=True,
            concrete_values={"MAXSZ": "1024"},
        )
        sg = _sg("memcpy", [g])
        results = check_guard_sufficiency(sg, buffer_size=4096)
        assert len(results) >= 1
        r = results[0]
        assert r.feasible is True
        assert r.guard_sufficient is False

    def test_no_resolvable_guards(self):
        g = _guard("len < limit", resolvable=False, concrete_values={})
        sg = _sg("memcpy", [g])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert results == []

    def test_no_buffer_size(self):
        g = _guard(
            "len < MAX",
            resolvable=True,
            concrete_values={"MAX": "1024"},
        )
        sg = _sg("memcpy", [g])
        results = check_guard_sufficiency(sg)  # no buffer_size
        assert len(results) >= 1
        # Without buffer_size, can't do arithmetic check
        r = results[0]
        # Should still extract the constraint even if verdict is None
        assert r.concrete_values

    def test_multiple_constraints_tightest_wins(self):
        """Guard with two upper bounds — tightest determines sufficiency.

        A non-negative lower bound is also required (soundness: signed
        negative values wrap to huge size_t at the sink).
        """
        # "len >= 0 && len < 4096 && len < 256" with buffer=256
        # Tightest: max_allowed=255 <= 256 → sufficient
        g = _guard(
            "len >= 0 && len < MAX_SIZE && len < LIMIT",
            resolvable=True,
            concrete_values={"MAX_SIZE": "4096", "LIMIT": "256"},
        )
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "len"])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        r = results[0]
        assert r.feasible is False  # tightest constraint fits
        assert r.guard_sufficient is True

    def test_multiple_constraints_all_too_loose(self):
        """Guard with two upper bounds, both exceed buffer."""
        # "len < 4096 && len < 1024" with buffer=256
        # Tightest: max_allowed=1023 > 256 → insufficient
        g = _guard(
            "len < MAX_SIZE && len < MID",
            resolvable=True,
            concrete_values={"MAX_SIZE": "4096", "MID": "1024"},
        )
        sg = _sg("memcpy", [g])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        r = results[0]
        assert r.feasible is True  # even tightest is too loose
        assert r.guard_sufficient is False

    def test_to_dict(self):
        g = _guard(
            "n < 100",
            resolvable=True,
            concrete_values={"X": "100"},
        )
        sg = _sg("memcpy", [g])
        results = check_guard_sufficiency(sg, buffer_size=256)
        if results:
            d = results[0].to_dict()
            assert "guard_text" in d
            assert "reasoning" in d


# ---------------------------------------------------------------------------
# Batch API
# ---------------------------------------------------------------------------


class TestCheckAllSufficiency:
    def test_batch_with_sizes(self):
        g1 = _guard("len < MAX", resolvable=True, concrete_values={"MAX": "4096"})
        # Sufficiency needs the non-negative lower bound (signed-wrap
        # soundness) — see test_upper_bound_alone_not_sufficient_signed_wrap.
        g2 = _guard(
            "n > 0 && n <= SIZE",
            resolvable=True, concrete_values={"SIZE": "128"},
        )
        guards = [
            _sg("memcpy", [g1], line=10),
            _sg("memcpy", [g2], line=20, sink_args=["dst", "src", "n"]),
        ]
        results = check_all_sufficiency(
            guards,
            buffer_sizes={10: 256, 20: 256},
        )
        assert len(results) == 2
        # First: 4096 > 256 → insufficient
        assert results[0][0].feasible is True
        # Second: 128 <= 256 → sufficient
        assert results[1][0].feasible is False


class TestNonProofsAreInconclusive:
    """Non-proofs (consistency SAT, vacuous single-variable alloc
    check) must never come back as guard_sufficient=True."""

    def test_consistency_check_is_not_a_sufficiency_verdict(self):
        # Non-memcpy/non-alloc sinks have no sufficiency model; the
        # consistency check used to return feasible=False (== guard
        # sufficient) for EVERY resolvable guard.
        g = _guard(
            "x < LIMIT", resolvable=True, concrete_values={"LIMIT": "10"},
        )
        sg = _sg("system", [g])
        results = check_guard_sufficiency(sg)
        assert len(results) >= 1
        for r in results:
            assert r.guard_sufficient is not True

    def test_alloc_single_var_is_inconclusive(self):
        # One constrained variable gives the multiplication-overflow
        # model nothing to check — the old code declared the guard
        # sufficient from that vacuum.
        g = _guard(
            "n > N0", resolvable=True, concrete_values={"N0": "0"},
        )
        sg = _sg("malloc", [g])
        results = check_guard_sufficiency(sg)
        assert len(results) >= 1
        for r in results:
            assert r.guard_sufficient is not True

    def test_alloc_signed_guard_not_encoded_unsigned(self):
        import pytest
        pytest.importorskip("z3")
        from core.audit.condition_smt import (
            BoundsConstraint,
            _z3_alloc_overflow_check,
        )
        # ``n > -1 && m > -1`` are signed guards; the old unsigned
        # encoding (UGT(n, 0xFF..FF)) was unsatisfiable, so the
        # multiplication query was vacuously UNSAT and the check said
        # 'cannot overflow'.  Signed encoding admits huge values.
        out = _z3_alloc_overflow_check([
            BoundsConstraint("n", ">", -1, "n > -1"),
            BoundsConstraint("m", ">", -1, "m > -1"),
        ])
        assert out[0] is True

    def test_alloc_genuine_no_overflow_proof_kept(self):
        import pytest
        pytest.importorskip("z3")
        from core.audit.condition_smt import (
            BoundsConstraint,
            _z3_alloc_overflow_check,
        )
        # The no-overflow proof also needs the size-argument binding:
        # the bounded variables must be the ones the allocation sizes.
        out = _z3_alloc_overflow_check([
            BoundsConstraint("n", ">", 0, "n > 0"),
            BoundsConstraint("n", "<", 100, "n < 100"),
            BoundsConstraint("m", ">", 0, "m > 0"),
            BoundsConstraint("m", "<", 100, "m < 100"),
        ], ["n", "m"])
        assert out[0] is False


# ── Safety contract compliance ──────────────────────────────────────────


class TestContractCompliance:
    def test_assert_boost_only_succeeds(self):
        from core.audit.safety_contract import assert_boost_only
        assert_boost_only("condition_smt")

    def test_suppress_evidence_raises(self):
        import pytest

        from core.audit.safety_contract import ContractViolation, SuppressEvidence
        with pytest.raises(ContractViolation):
            SuppressEvidence(
                source="condition_smt",
                verdict="guard_sufficient",
                reason="test",
            )

    def test_boost_evidence_allowed(self):
        from core.audit.safety_contract import BoostEvidence
        ev = BoostEvidence(
            source="condition_smt",
            action="add_finding",
            description="guard insufficient — overflow still possible",
        )
        assert ev.source == "condition_smt"
        assert ev.action == "add_finding"


# ── Safety contract blind spots (adversarial) ──────────────────────────


class TestBlindSpotSufficientGuardIsBoost:
    """A 'guard sufficient' SMT result must be context injection (boost),
    not suppression.

    When SMT proves a guard IS sufficient, the orchestrator injects that
    as context for the LLM ('this guard looks adequate — focus elsewhere').
    It must NEVER suppress or remove the function from review.
    """

    def test_sufficient_guard_is_not_feasible(self):
        # Non-negative lower bound included: sufficiency requires
        # excluding the signed-negative wrap case, not just the upper
        # bound.
        g = _guard(
            "n >= 0 && n <= LIMIT",
            resolvable=True,
            concrete_values={"LIMIT": "128"},
        )
        sg = _sg("memcpy", [g], line=10, sink_args=["dst", "src", "n"])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        assert results[0].feasible is False
        assert results[0].guard_sufficient is True


# ── Polarity-aware constraints ────────────────────────────────────────


class TestConstraintsForGuard:
    def test_required_polarity_passes_through(self):
        g = _guard("len < 256", resolvable=True, concrete_values={})
        cs = constraints_for_guard(g)
        assert len(cs) >= 1
        assert cs[0].operator == "<"
        assert cs[0].bound_value == 256

    def test_excluded_polarity_negates(self):
        g = GuardCondition(
            text="len < 256", category="bounds", polarity="excluded",
            line=1, resolvable=True, concrete_values={},
        )
        cs = constraints_for_guard(g)
        assert len(cs) >= 1
        assert cs[0].operator == ">="
        assert cs[0].bound_value == 256

    def test_negated_guard_polarity_negates(self):
        # Early-return guard: if (len > 256) return;  — the taken
        # path satisfies the negation, exactly like the else-branch
        # case for the SMT encoding.
        g = GuardCondition(
            text="len > 256", category="bounds",
            polarity="negated_guard",
            line=1, resolvable=True, concrete_values={},
        )
        cs = constraints_for_guard(g)
        assert len(cs) >= 1
        assert cs[0].operator == "<="
        assert cs[0].bound_value == 256

    def test_negated_guard_conjunction_returns_none(self):
        g = GuardCondition(
            text="len > 256 && flag", category="bounds",
            polarity="negated_guard",
            line=1, resolvable=True, concrete_values={},
        )
        assert constraints_for_guard(g) is None

    def test_excluded_lte_becomes_gt(self):
        g = GuardCondition(
            text="n <= 100", category="bounds", polarity="excluded",
            line=1, resolvable=True, concrete_values={},
        )
        cs = constraints_for_guard(g)
        found = [c for c in cs if c.variable == "n"]
        assert found
        assert found[0].operator == ">"
        assert found[0].bound_value == 100

    def test_respect_polarity_false_skips_negation(self):
        g = GuardCondition(
            text="x < 10", category="bounds", polarity="excluded",
            line=1, resolvable=True, concrete_values={},
        )
        cs = constraints_for_guard(g, respect_polarity=False)
        assert cs[0].operator == "<"


class TestBooleanStructureGate:
    """Guards whose boolean structure the conjunctive model cannot
    represent must yield ``None`` (inconclusive) — flattening their
    atoms into a conjunction fabricates false UNSAT proofs that used
    to become 'dead path' / 'guard sufficient' verdicts (soundness)."""

    def test_disjunction_returns_none(self):
        g = _guard("n == 0 || n == 1", resolvable=True, concrete_values={})
        assert constraints_for_guard(g) is None

    def test_logical_not_returns_none(self):
        g = _guard(
            "!(len < 1024) && len < 2048",
            resolvable=True, concrete_values={},
        )
        assert constraints_for_guard(g) is None

    def test_ternary_returns_none(self):
        g = _guard(
            "(mode ? a : b) < 10", resolvable=True, concrete_values={},
        )
        assert constraints_for_guard(g) is None

    def test_python_or_returns_none(self):
        g = _guard("n == 0 or n == 1", resolvable=True, concrete_values={})
        assert constraints_for_guard(g) is None

    def test_not_equal_is_not_logical_not(self):
        g = _guard("n != 0", resolvable=True, concrete_values={})
        cs = constraints_for_guard(g)
        assert cs is not None
        assert cs[0].operator == "!="

    def test_excluded_conjunction_returns_none(self):
        # NOT (a >= 10 AND a <= 20) is a DISJUNCTION (De Morgan);
        # negating the atoms individually asserts a < 10 AND a > 20 —
        # UNSAT — a false 'dead path' for a trivially reachable sink.
        g = GuardCondition(
            text="a >= 10 && a <= 20", category="bounds",
            polarity="excluded", line=1, resolvable=True,
            concrete_values={},
        )
        assert constraints_for_guard(g) is None

    def test_excluded_partial_extraction_returns_none(self):
        # ``flag && a < 10`` extracts only one atom; negating it alone
        # over-constrains (flag=false alone satisfies the negation).
        g = GuardCondition(
            text="flag && a < 10", category="bounds",
            polarity="excluded", line=1, resolvable=True,
            concrete_values={},
        )
        assert constraints_for_guard(g) is None

    def test_excluded_single_atom_still_negates(self):
        g = GuardCondition(
            text="a < 10", category="bounds", polarity="excluded",
            line=1, resolvable=True, concrete_values={},
        )
        cs = constraints_for_guard(g)
        assert cs is not None
        assert cs[0].operator == ">="

    def test_required_conjunction_still_extracts(self):
        g = _guard("a > 0 && a < 10", resolvable=True, concrete_values={})
        cs = constraints_for_guard(g)
        assert cs is not None
        assert len(cs) == 2


# ── Path feasibility ─────────────────────────────────────────────────


class TestPathFeasibility:
    def test_consistent_guards_feasible(self):
        guards = [
            _guard("x > 0", resolvable=True, concrete_values={}),
            _guard("x < 100", resolvable=True, concrete_values={}),
        ]
        result = check_path_feasibility(guards)
        assert result.feasible is True
        assert result.guard_count == 2

    def test_contradictory_guards_infeasible(self):
        guards = [
            _guard("x < 10", resolvable=True, concrete_values={}),
            _guard("x > 20", resolvable=True, concrete_values={}),
        ]
        result = check_path_feasibility(guards)
        assert result.feasible is False

    def test_polarity_negation_creates_contradiction(self):
        g1 = _guard("x < 10", resolvable=True, concrete_values={})
        g2 = GuardCondition(
            text="x < 5", category="bounds", polarity="excluded",
            line=2, resolvable=True, concrete_values={},
        )
        # x < 10 AND x >= 5 → feasible (x=5..9)
        result = check_path_feasibility([g1, g2])
        assert result.feasible is True

    def test_no_extractable_constraints(self):
        guards = [_guard("flag == TRUE", resolvable=False, concrete_values={})]
        result = check_path_feasibility(guards)
        assert result.feasible is None

    def test_equality_contradiction(self):
        guards = [
            _guard("x == 5", resolvable=True, concrete_values={}),
            _guard("x == 10", resolvable=True, concrete_values={}),
        ]
        result = check_path_feasibility(guards)
        # Neither a solver result nor the scalar fallback may call this
        # feasible, including when a worker is unavailable.
        if result.feasible is not None:
            assert result.feasible is False

    def test_disjunctive_guard_is_inconclusive_not_dead_path(self):
        # ``n == 0 || n == 1`` is trivially satisfiable; the old flat
        # conjunction asserted n==0 AND n==1 → UNSAT → false 'dead
        # path' that resolved the function dormant without LLM review.
        guards = [
            _guard("n == 0 || n == 1", resolvable=True, concrete_values={}),
        ]
        result = check_path_feasibility(guards)
        assert result.feasible is not False
        assert result.feasible is None

    def test_excluded_conjunction_is_inconclusive_not_dead_path(self):
        # sink after ``if (a >= 10 && a <= 20) return;`` is reachable
        # for a=5 — per-atom negation used to produce a false UNSAT.
        g = GuardCondition(
            text="a >= 10 && a <= 20", category="bounds",
            polarity="excluded", line=1, resolvable=True,
            concrete_values={},
        )
        result = check_path_feasibility([g])
        assert result.feasible is not False
        assert result.feasible is None

    def test_negated_guard_is_inconclusive(self):
        # ``!(len < 1024) && len < 2048`` admits len in [1024, 2048);
        # ignoring the ``!`` used to yield witness len=0 (inverted
        # polarity).  Unmodeled → inconclusive.
        guards = [
            _guard(
                "!(len < 1024) && len < 2048",
                resolvable=True, concrete_values={},
            ),
        ]
        result = check_path_feasibility(guards)
        assert result.feasible is None

    def test_unmodeled_guard_cannot_poison_other_guards(self):
        # A tractable contradiction alongside an unmodeled guard is
        # still a sound UNSAT (weakening the conjunction preserves
        # infeasibility proofs), but the unmodeled guard itself never
        # contributes atoms.
        guards = [
            _guard("x < 10", resolvable=True, concrete_values={}),
            _guard("x > 20", resolvable=True, concrete_values={}),
            _guard("n == 0 || n == 1", resolvable=True, concrete_values={}),
        ]
        result = check_path_feasibility(guards)
        assert result.feasible is False


class TestGuardTextCheckersBooleanStructure:
    """The child-side guard-text feasibility checks must not conjoin
    atoms from ||/!/ternary guards — the resulting UNSAT would be a
    false 'no bypass possible' / 'leak path unreachable' refutation."""

    def test_auth_bypass_disjunction_not_refuted(self):
        import pytest
        pytest.importorskip("z3")
        from core.audit.condition_smt import _z3_auth_bypass_check
        out = _z3_auth_bypass_check(
            "(n == 0 || n == 1)", ["capability:capable(CAP_SYS_ADMIN)"],
        )
        # The guard is trivially satisfiable (n=0) — the bypass is
        # feasible, never "no bypass possible".
        assert out.bypass_found is True
        assert "no bypass possible" not in out.reasoning

    def test_resource_leak_disjunction_not_refuted(self):
        import pytest
        pytest.importorskip("z3")
        from core.audit.condition_smt import _z3_resource_leak_check
        out = _z3_resource_leak_check(
            "(n == 0 || n == 1)", "buf", "malloc", 3, 8,
        )
        assert out.leak_found is True
        assert "unreachable" not in out.reasoning

    def test_lock_discipline_disjunction_not_refuted(self):
        import pytest
        pytest.importorskip("z3")
        from core.audit.condition_smt import _z3_lock_discipline_check
        out = _z3_lock_discipline_check(
            "(n == 0 || n == 1)", "spin_lock", 12,
        )
        assert out.violation_found is True
        assert "unreachable" not in out.reasoning

    def test_auth_bypass_conjunctive_unsat_still_refutes(self):
        import pytest
        pytest.importorskip("z3")
        from core.audit.condition_smt import _z3_auth_bypass_check
        # Genuine UNSAT on a correctly-modeled conjunctive guard keeps
        # its boost value (real dead-guard proof).
        out = _z3_auth_bypass_check(
            "(n < 5 && n > 10)", ["capability:capable(CAP_SYS_ADMIN)"],
        )
        assert out.bypass_found is False


# ── Signed/unsigned mismatch ─────────────────────────────────────────


class TestSignedMismatch:
    def test_detects_mismatch(self):
        g = _guard("size < 1024", resolvable=True, concrete_values={})
        result = check_signed_mismatch(g, var_is_unsigned=True, comparison_is_signed=True, bit_width=32)
        assert result.mismatch is True
        assert result.variable == "size"
        assert result.witness is not None
        assert result.witness["size"] < 0

    def test_no_mismatch_when_signed(self):
        g = _guard("size < 1024", resolvable=True, concrete_values={})
        result = check_signed_mismatch(g, var_is_unsigned=False)
        assert result.mismatch is False

    def test_greater_than_not_affected(self):
        g = _guard("size > 0", resolvable=True, concrete_values={})
        result = check_signed_mismatch(g, var_is_unsigned=True, bit_width=32)
        assert result.mismatch is False

    def test_unknown_signedness_makes_no_claim(self):
        # Regression (verdict soundness): the old default assumed every
        # variable unsigned, stamping a witness-carrying
        # signed_mismatch finding per resolvable upper-bound guard.
        g = _guard("size < 1024", resolvable=True, concrete_values={})
        result = check_signed_mismatch(g)
        assert result.mismatch is False
        assert result.witness is None

    def test_declared_unsigned_type_does_not_establish_signed_comparison(self):
        g = _guard("size < 1024", resolvable=True, concrete_values={})
        src = "int f(size_t size) { if (size < 1024) use(size); }"
        result = check_signed_mismatch(g, source=src)
        assert result.mismatch is False
        assert result.witness is None
        assert "semantics not established" in result.reasoning

    def test_declared_signed_type_suppresses_claim(self):
        g = _guard("size < 1024", resolvable=True, concrete_values={})
        src = "int f(int size) { if (size < 1024) use(size); }"
        result = check_signed_mismatch(g, source=src)
        assert result.mismatch is False

    def test_declared_signedness_helper(self):
        from core.audit.condition_smt import declared_signedness
        src = (
            "int f(size_t a, int b, unsigned int c, u32 d, s64 e) {\n"
            "    long g;\n"
            "}\n"
        )
        assert declared_signedness("a", src) is True
        assert declared_signedness("b", src) is False
        assert declared_signedness("c", src) is True
        assert declared_signedness("d", src) is True
        assert declared_signedness("e", src) is False
        assert declared_signedness("g", src) is False
        assert declared_signedness("missing", src) is None


class TestFindEnclosingGuard:
    """Scope-aware guard attribution (verdict soundness): a return
    after a CLOSED if-block used to inherit that block's condition,
    and the downstream Z3 feasibility calls reasoned about a guard
    that does not gate the return."""

    def _find(self, src: str, ret_line: int) -> str:
        from core.audit.condition_smt import _find_enclosing_guard
        return _find_enclosing_guard(src.split("\n"), ret_line)

    def test_braced_if_encloses_return(self):
        src = "int f(void) {\nif (n > 5) {\nreturn 0;\n}\n}\n"
        # return on line index 2
        assert self._find(src, 2) == "(n > 5)"

    def test_closed_block_does_not_leak_guard(self):
        src = (
            "int f(void) {\n"
            "if (n > 5) {\n"
            "do_stuff();\n"
            "}\n"
            "return 0;\n"
            "}\n"
        )
        # return on line index 4 is OUTSIDE the if-block
        assert self._find(src, 4) == ""

    def test_braceless_if_still_found(self):
        src = "int f(void) {\nif (x < 0)\nreturn -1;\n}\n"
        assert self._find(src, 2) == "(x < 0)"

    def test_braceless_if_not_adjacent_not_used(self):
        src = (
            "int f(void) {\n"
            "if (x < 0)\n"
            "log();\n"
            "return -1;\n"
            "}\n"
        )
        assert self._find(src, 3) == ""

    def test_else_branch_does_not_inherit_condition(self):
        src = (
            "int f(void) {\n"
            "if (a > 0) {\n"
            "work();\n"
            "} else {\n"
            "return 0;\n"
            "}\n"
            "}\n"
        )
        # Returning "(a > 0)" here would invert the polarity of the
        # feasibility question.
        assert self._find(src, 4) == ""

    def test_nested_closed_block_inside_enclosing_if(self):
        src = (
            "int f(void) {\n"
            "if (a < 10) {\n"
            "if (b) {\n"
            "x();\n"
            "}\n"
            "return 0;\n"
            "}\n"
            "}\n"
        )
        assert self._find(src, 5) == "(a < 10)"

    def test_if_through_non_if_scope(self):
        src = (
            "int f(void) {\n"
            "if (a < 10) {\n"
            "while (x) {\n"
            "return 0;\n"
            "}\n"
            "}\n"
            "}\n"
        )
        assert self._find(src, 3) == "(a < 10)"


# ── Off-by-one detection ─────────────────────────────────────────────


class TestOffByOne:
    def test_strncat_off_by_one(self):
        g = _guard("len <= BUF", resolvable=True, concrete_values={"BUF": "256"})
        sg = _sg("strncat", [g])
        results = check_off_by_one(sg, buffer_size=256)
        assert len(results) == 1
        assert results[0].feasible is True
        assert "off-by-one" in results[0].reasoning
        assert results[0].witness == {"len": 256}

    def test_strncat_strict_less_off_by_one(self):
        g = _guard("len < SIZE", resolvable=True, concrete_values={"SIZE": "257"})
        sg = _sg("strncat", [g])
        results = check_off_by_one(sg, buffer_size=256)
        assert len(results) == 1
        assert results[0].feasible is True
        assert results[0].witness == {"len": 256}

    def test_strncpy_not_off_by_one(self):
        """strncpy writes exactly n bytes, no +1 — should not trigger."""
        g = _guard("len <= BUF", resolvable=True, concrete_values={"BUF": "256"})
        sg = _sg("strncpy", [g])
        results = check_off_by_one(sg, buffer_size=256)
        assert len(results) == 0

    def test_memcpy_not_null_terminated(self):
        g = _guard("len <= BUF", resolvable=True, concrete_values={"BUF": "256"})
        sg = _sg("memcpy", [g])
        results = check_off_by_one(sg, buffer_size=256)
        assert results == []

    def test_no_buffer_size(self):
        g = _guard("len <= BUF", resolvable=True, concrete_values={"BUF": "256"})
        sg = _sg("strncpy", [g])
        results = check_off_by_one(sg, buffer_size=None)
        assert results == []

    def test_sufficient_guard_no_off_by_one(self):
        g = _guard("len < BUF", resolvable=True, concrete_values={"BUF": "256"})
        sg = _sg("strncpy", [g])
        results = check_off_by_one(sg, buffer_size=256)
        assert results == []


# ── Witness in to_dict ───────────────────────────────────────────────


class TestWitnessInToDict:
    def test_witness_included(self):
        from core.audit.condition_smt import SmtSufficiencyResult
        r = SmtSufficiencyResult(
            guard_text="n < 4096", feasible=True, reasoning="overflow",
            witness={"n": 4095},
        )
        d = r.to_dict()
        assert d["witness"] == {"n": 4095}

    def test_path_feasibility_to_dict(self):
        from core.audit.condition_smt import PathFeasibilityResult
        r = PathFeasibilityResult(
            feasible=False, reasoning="dead path", guard_count=2,
        )
        d = r.to_dict()
        assert d["feasible"] is False
        assert d["guard_count"] == 2

    def test_signed_mismatch_to_dict(self):
        from core.audit.condition_smt import SignedMismatchResult
        r = SignedMismatchResult(
            mismatch=True, variable="size",
            reasoning="wraps", witness={"size": -1},
        )
        d = r.to_dict()
        assert d["mismatch"] is True
        assert d["witness"] == {"size": -1}


class TestRaceProtectionIdentity:
    """Race-protection claims must respect lock identity, accessor
    binding, and RCU derivation — the previous version counted ANY
    lock scope, ANY atomic call on the line, and ANY line inside an
    RCU section as protection for every access."""

    def test_different_lock_objects_do_not_protect_shared_field(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *a, struct bar *b, struct shared *s) {\n"
            "    spin_lock(&a->lock);\n"
            "    s->count++;\n"
            "    spin_unlock(&a->lock);\n"
            "    spin_lock(&b->lock);\n"
            "    s->count--;\n"
            "    spin_unlock(&b->lock);\n"
            "}\n"
        )
        r = check_race_protection(src)
        # a->lock and b->lock are different locks: the two s->count
        # accesses are NOT serialised against each other.
        assert r.protected is False

    def test_same_lock_object_protects_shared_field(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct shared *s) {\n"
            "    spin_lock(&s->lock);\n"
            "    s->count++;\n"
            "    spin_unlock(&s->lock);\n"
            "    spin_lock(&s->lock);\n"
            "    s->count--;\n"
            "    spin_unlock(&s->lock);\n"
            "}\n"
        )
        r = check_race_protection(src)
        assert r.protected is True

    def test_atomic_on_line_does_not_protect_other_access(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *a, struct bar *b) {\n"
            "    int v = atomic_read(&a->cnt) + b->data;\n"
            "}\n"
        )
        r = check_race_protection(src)
        # b->data is not inside the atomic accessor's arguments.
        assert r.protected is False
        assert r.unprotected_accesses >= 1

    def test_plain_deref_in_rcu_scope_not_protected(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *b) {\n"
            "    rcu_read_lock();\n"
            "    int v = b->count;\n"
            "    rcu_read_unlock();\n"
            "}\n"
        )
        r = check_race_protection(src)
        # b was not obtained via rcu_dereference — the RCU section
        # does not serialise b->count.
        assert r.protected is False

    def test_rcu_dereferenced_pointer_protected(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *b) {\n"
            "    rcu_read_lock();\n"
            "    struct baz *p = rcu_dereference(b->ptr);\n"
            "    int v = p->count;\n"
            "    rcu_read_unlock();\n"
            "}\n"
        )
        r = check_race_protection(src)
        assert r.protected is True

    def test_protected_reasoning_labels_residual_uncertainty(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *b) {\n"
            "    spin_lock(&b->lock);\n"
            "    b->count++;\n"
            "    spin_unlock(&b->lock);\n"
            "}\n"
        )
        r = check_race_protection(src)
        assert r.protected is True
        assert "heuristic" in r.reasoning


class TestCheckRaceProtection:
    def test_all_inside_spinlock(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *b) {\n"
            "    spin_lock(&b->lock);\n"
            "    b->count++;\n"
            "    b->flags |= 1;\n"
            "    spin_unlock(&b->lock);\n"
            "}\n"
        )
        r = check_race_protection(src)
        assert r.protected is True
        assert r.total_accesses >= 2

    def test_unprotected_access(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *b) {\n"
            "    int v = b->count;\n"
            "    v++;\n"
            "    b->count = v;\n"
            "}\n"
        )
        r = check_race_protection(src)
        assert r.protected is False
        assert r.unprotected_accesses > 0

    def test_raw_spinlock_scope_recognised(self):
        """raw_spin_lock_irqsave has no `\\b` match inside its unlock
        twin, so it needs its own seed pair — without it fully locked
        code reads as unprotected."""
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *b) {\n"
            "    unsigned long flags;\n"
            "    raw_spin_lock_irqsave(&b->lock, flags);\n"
            "    b->count++;\n"
            "    raw_spin_unlock_irqrestore(&b->lock, flags);\n"
            "}\n"
        )
        r = check_race_protection(src)
        assert r.protected is True

    def test_lock_sock_recognised(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "int check(struct socket *sock) {\n"
            "    struct sock *sk = sock->sk;\n"
            "    lock_sock(sk);\n"
            "    int v = sk->sk_state;\n"
            "    release_sock(sk);\n"
            "    return v;\n"
            "}\n"
        )
        # lock_sock/release_sock are pack-tier vocabulary now.
        from core.audit.vocab_packs import load_pack
        r = check_race_protection(src, load_pack("linux_kernel"))
        assert r.protected is True

    def test_rcu_accessor_in_rcu_scope(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *b) {\n"
            "    rcu_read_lock();\n"
            "    struct baz *p = rcu_dereference(b->ptr);\n"
            "    use(p);\n"
            "    rcu_read_unlock();\n"
            "}\n"
        )
        r = check_race_protection(src)
        assert r.protected is True

    def test_rcu_accessor_outside_rcu_scope(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *b) {\n"
            "    struct baz *p = rcu_dereference(b->ptr);\n"
            "    use(p);\n"
            "}\n"
        )
        r = check_race_protection(src)
        assert r.protected is False

    def test_atomic_accessor_counted(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *b) {\n"
            "    int v = atomic_read(&b->refcnt);\n"
            "    use(v);\n"
            "}\n"
        )
        r = check_race_protection(src)
        assert r.protected is True

    def test_init_deref_before_lock(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "int check(struct outer *o) {\n"
            "    struct inner *i = o->inner;\n"
            "    mutex_lock(&i->mtx);\n"
            "    i->val = 1;\n"
            "    mutex_unlock(&i->mtx);\n"
            "    return 0;\n"
            "}\n"
        )
        r = check_race_protection(src)
        assert r.protected is True

    def test_go_returns_not_applicable(self):
        from core.audit.condition_smt import check_race_protection
        src = "func foo() { }\npackage main\n"
        r = check_race_protection(src)
        assert r.protected is False
        assert "Go" in r.reasoning

    def test_no_accesses(self):
        from core.audit.condition_smt import check_race_protection
        src = "void foo(int x) { return x + 1; }\n"
        r = check_race_protection(src)
        assert r.protected is False
        assert "no struct" in r.reasoning

    def test_to_dict(self):
        from core.audit.condition_smt import check_race_protection
        src = (
            "void foo(struct bar *b) {\n"
            "    spin_lock(&b->lock);\n"
            "    b->x = 1;\n"
            "    spin_unlock(&b->lock);\n"
            "}\n"
        )
        r = check_race_protection(src)
        d = r.to_dict()
        assert d["protected"] is True
        assert "total_accesses" in d


class TestExtractLockObject:
    def test_simple_pointer(self):
        line = "    spin_lock(&ep->lock);"
        assert _extract_lock_object(line, line.index("(") + 1) == "ep->lock"

    def test_address_of_stripped(self):
        line = "    mutex_lock(&my_mutex);"
        assert _extract_lock_object(line, line.index("(") + 1) == "my_mutex"

    def test_with_flags_arg(self):
        line = "    spin_lock_irqsave(&ep->lock, flags);"
        assert _extract_lock_object(line, line.index("(") + 1) == "ep->lock"

    def test_no_args(self):
        line = "    rcu_read_lock();"
        assert _extract_lock_object(line, line.index("(") + 1) == ""


class TestCheckLockDiscipline:
    def test_balanced_single_lock(self):
        src = (
            "void foo(struct bar *b) {\n"
            "    spin_lock(&b->lock);\n"
            "    b->x = 1;\n"
            "    spin_unlock(&b->lock);\n"
            "}\n"
        )
        r = check_lock_discipline(src)
        assert not r.violation_found

    def test_unbalanced_single_lock(self):
        src = (
            "void foo(struct bar *b) {\n"
            "    spin_lock(&b->lock);\n"
            "    b->x = 1;\n"
            "    return;\n"
            "}\n"
        )
        r = check_lock_discipline(src)
        assert r.violation_found

    def test_two_different_locks_no_fp(self):
        """Regression: __ep_remove pattern — two distinct lock objects,
        each properly balanced.  Must NOT fire."""
        src = (
            "void __ep_remove(struct eventpoll *ep, struct epitem *epi) {\n"
            "    spin_lock(&file->f_lock);\n"
            "    list_del_init(&epi->fllink);\n"
            "    spin_unlock(&file->f_lock);\n"
            "\n"
            "    spin_lock_irq(&ep->lock);\n"
            "    list_del_init(&epi->rdllink);\n"
            "    spin_unlock_irq(&ep->lock);\n"
            "}\n"
        )
        r = check_lock_discipline(src)
        assert not r.violation_found

    def test_two_locks_one_unbalanced(self):
        """Two locks, but the second one has a return before release."""
        src = (
            "int foo(struct bar *b) {\n"
            "    spin_lock(&b->lock_a);\n"
            "    b->x = 1;\n"
            "    spin_unlock(&b->lock_a);\n"
            "\n"
            "    spin_lock(&b->lock_b);\n"
            "    if (b->err)\n"
            "        return -1;\n"
            "    spin_unlock(&b->lock_b);\n"
            "    return 0;\n"
            "}\n"
        )
        r = check_lock_discipline(src)
        assert r.violation_found

    def test_nested_locks_balanced(self):
        """Nested acquire of two different locks, both released."""
        src = (
            "void foo(struct bar *b) {\n"
            "    spin_lock(&b->outer);\n"
            "    spin_lock(&b->inner);\n"
            "    b->x = 1;\n"
            "    spin_unlock(&b->inner);\n"
            "    spin_unlock(&b->outer);\n"
            "}\n"
        )
        r = check_lock_discipline(src)
        assert not r.violation_found


# ---------------------------------------------------------------------------
# Go early-release hardening (Lever 4)
# ---------------------------------------------------------------------------


class TestGoEarlyReleaseHardening:
    """Lever 4: widened read pattern and defer handling."""

    def test_method_call_read(self):
        """val := obj.GetField() should be captured."""
        src = (
            "package main\n"
            "func foo(mu *sync.Mutex, s *State) {\n"
            "    mu.Lock()\n"
            "    val := s.GetField()\n"
            "    mu.Unlock()\n"
            "    fmt.Println(val)\n"
            "}\n"
        )
        r = check_early_release(src)
        assert r.early_release_found
        assert "val" in r.variable

    def test_multi_return_read(self):
        """val, err := obj.Method() should be captured."""
        src = (
            "package main\n"
            "func foo(mu *sync.Mutex, s *State) {\n"
            "    mu.Lock()\n"
            "    val, err := s.Load()\n"
            "    mu.Unlock()\n"
            "    if err != nil { return }\n"
            "    use(val)\n"
            "}\n"
        )
        r = check_early_release(src)
        assert r.early_release_found
        assert "val" in r.variable

    def test_defer_use_after_function_body(self):
        """defer Unlock: variable used after all lock-protected code."""
        src = (
            "package main\n"
            "func foo(mu *sync.Mutex, s *State) int {\n"
            "    mu.Lock()\n"
            "    defer mu.Unlock()\n"
            "    val := s.counter\n"
            "    // long computation\n"
            "    time.Sleep(time.Second)\n"
            "    return val\n"
            "}\n"
        )
        r = check_early_release(src)
        assert not r.early_release_found

    def test_defer_with_post_unlock_use(self):
        """defer Unlock + variable used well after function return boundary."""
        src = (
            "package main\n"
            "func process(mu *sync.Mutex, s *State) {\n"
            "    mu.Lock()\n"
            "    defer mu.Unlock()\n"
            "    val := s.data\n"
            "}\n"
            "\n"
            "func other(val int) {\n"
            "    use(val)\n"
            "}\n"
        )
        r = check_early_release(src)
        assert not r.early_release_found

    def test_explicit_unlock_still_detected(self):
        """Explicit Unlock → variable used after: still flagged."""
        src = (
            "package main\n"
            "func foo(mu *sync.Mutex, s *State) {\n"
            "    mu.Lock()\n"
            "    val := s.counter\n"
            "    mu.Unlock()\n"
            "    fmt.Println(val)\n"
            "}\n"
        )
        r = check_early_release(src)
        assert r.early_release_found

    def test_no_race_when_unused(self):
        """Variable read under lock but not used after unlock."""
        src = (
            "package main\n"
            "func foo(mu *sync.Mutex, s *State) {\n"
            "    mu.Lock()\n"
            "    val := s.counter\n"
            "    mu.Unlock()\n"
            "    unrelated()\n"
            "}\n"
        )
        r = check_early_release(src)
        assert not r.early_release_found


# ---------------------------------------------------------------------------
# Per-field lock domain (Lever 5)
# ---------------------------------------------------------------------------


class TestCorrelatedFieldAccess:
    """Lever 5: security-relevant field correlation."""

    def test_cred_and_mm_under_different_locks(self):
        """Two security fields under different locks → mismatch."""
        src = (
            "void task_dump_owner(struct task_struct *task) {\n"
            "    rcu_read_lock();\n"
            "    cred = task->cred;\n"
            "    uid = cred->uid;\n"
            "    rcu_read_unlock();\n"
            "    task_lock(task);\n"
            "    mm = task->mm;\n"
            "    dumpable = mm->dumpable;\n"
            "    task_unlock(task);\n"
            "}\n"
        )
        # task_lock and the cred/mm/dumpable fields are pack-tier now.
        from core.audit.vocab_packs import load_pack
        r = check_lock_domain(src, load_pack("linux_kernel"))
        assert r.mismatch_found
        assert "cred" in r.field or "mm" in r.field or "dumpable" in r.field

    def test_same_security_field_same_lock(self):
        """Same security field under same lock → no mismatch."""
        src = (
            "void safe(struct task_struct *task) {\n"
            "    rcu_read_lock();\n"
            "    cred = task->cred;\n"
            "    uid = task->uid;\n"
            "    rcu_read_unlock();\n"
            "}\n"
        )
        r = check_lock_domain(src)
        assert not r.mismatch_found

    def test_non_security_fields_not_flagged(self):
        """Non-security fields under different locks → no flag."""
        src = (
            "void read_stats(struct device *dev) {\n"
            "    spin_lock(&dev->stats_lock);\n"
            "    a = dev->rx_count;\n"
            "    spin_unlock(&dev->stats_lock);\n"
            "    spin_lock(&dev->tx_lock);\n"
            "    b = dev->tx_count;\n"
            "    spin_unlock(&dev->tx_lock);\n"
            "}\n"
        )
        r = check_lock_domain(src)
        assert not r.mismatch_found

    def test_security_fields_constant(self):
        """Seed set stays generic; kernel fields come from the pack."""
        from core.audit.vocab_packs import load_pack

        assert _SECURITY_FIELDS == frozenset({"uid", "euid", "gid", "egid"})
        pack = load_pack("linux_kernel")
        combined = _SECURITY_FIELDS | pack.security_fields
        for f in ("cred", "uid", "mm", "dumpable", "seccomp"):
            assert f in combined


# ---------------------------------------------------------------------------
# Guard-exit unlock classifier (shared by Go and C)
# ---------------------------------------------------------------------------


class TestGuardExitUnlock:
    """Shared _find_scope_unlock classifier."""

    def test_c_guard_exit_skipped(self):
        """unlock+return is a guard exit; race uses the next unlock."""
        src = (
            "void process(struct foo *f) {\n"
            "    spin_lock(&f->lock);\n"
            "    if (f->error) {\n"
            "        spin_unlock(&f->lock);\n"
            "        return;\n"
            "    }\n"
            "    val = f->data;\n"
            "    spin_unlock(&f->lock);\n"
            "    val->next = NULL;\n"
            "}\n"
        )
        r = check_early_release(src)
        assert r.early_release_found
        assert r.release_line == 8
        assert r.use_line == 9

    def test_c_goto_guard_exit_skipped(self):
        """unlock+goto is a guard exit in C kernel code."""
        src = (
            "void process(struct foo *f) {\n"
            "    spin_lock(&f->lock);\n"
            "    if (f->error) {\n"
            "        spin_unlock(&f->lock);\n"
            "        goto out;\n"
            "    }\n"
            "    val = f->data;\n"
            "    spin_unlock(&f->lock);\n"
            "    val->next = NULL;\n"
            "out:\n"
            "    return;\n"
            "}\n"
        )
        r = check_early_release(src)
        assert r.early_release_found
        assert r.release_line == 8

    def test_c_no_guard_exit(self):
        """First unlock IS the scope end when not followed by return."""
        src = (
            "void simple(struct foo *f) {\n"
            "    spin_lock(&f->lock);\n"
            "    val = f->data;\n"
            "    spin_unlock(&f->lock);\n"
            "    val->next = NULL;\n"
            "}\n"
        )
        r = check_early_release(src)
        assert r.early_release_found
        assert r.release_line == 4

    def test_go_guard_exit_skipped(self):
        """Go: RUnlock+return guard exit skipped."""
        src = (
            "package main\n"
            "func foo(mu *sync.Mutex, s *State) {\n"
            "    mu.Lock()\n"
            "    if s.err != nil {\n"
            "        mu.Unlock()\n"
            "        return\n"
            "    }\n"
            "    val := s.data\n"
            "    mu.Unlock()\n"
            "    fmt.Println(val)\n"
            "}\n"
        )
        r = check_early_release(src)
        assert r.early_release_found
        assert r.release_line == 9
        assert "val" in r.variable

    def test_go_conditional_unlock(self):
        """Go: conditional unlock (else branch) is the scope boundary.

        Mirrors Rows.Scan: variable read under lock, guard-exit unlocks
        skipped, conditional unlock in else branch, variable used after.
        """
        src = (
            "package main\n"
            "func scan(rs *Rows, dest []any) error {\n"
            "    rs.closemu.RLock()\n"
            "    if rs.lasterr != nil {\n"
            "        rs.closemu.RUnlock()\n"
            "        return rs.lasterr\n"
            "    }\n"
            "    cols := rs.lastcols\n"
            "    if cond(dest) {\n"
            "        rs.hold = true\n"
            "    } else {\n"
            "        rs.closemu.RUnlock()\n"
            "    }\n"
            "    use(cols)\n"
            "    return nil\n"
            "}\n"
        )
        r = check_early_release(src)
        assert r.early_release_found
        assert r.release_line == 12
        assert "cols" in r.variable

    def test_all_unlocks_are_guard_exits(self):
        """When every unlock is a guard exit, no scope end found → clean."""
        src = (
            "package main\n"
            "func guarded(mu *sync.Mutex, s *State) error {\n"
            "    mu.Lock()\n"
            "    if s.err != nil {\n"
            "        mu.Unlock()\n"
            "        return s.err\n"
            "    }\n"
            "    if s.closed {\n"
            "        mu.Unlock()\n"
            "        return ErrClosed\n"
            "    }\n"
            "    return nil\n"
            "}\n"
        )
        r = check_early_release(src)
        assert not r.early_release_found


class TestParsedIntContract:
    """Text-parsed integers consumed without a range check."""

    _VULN = (
        "func (s *Scanner) applyLineDirective(next int, text []byte) {\n"
        "\tline, err := strconv.Atoi(string(text))\n"
        "\tif err != nil {\n"
        "\t\treturn\n"
        "\t}\n"
        "\ts.file.SetLinePosition(next, filename, line, line)\n"
        "}\n"
    )

    def test_unchecked_parse_to_callee_flagged(self):
        from core.audit.condition_smt import check_parsed_int_contract

        r = check_parsed_int_contract(self._VULN)
        assert r.narrowing_found
        assert "SetLinePosition" in r.reasoning
        assert "NO range check" in r.reasoning

    def test_range_checked_parse_silent(self):
        from core.audit.condition_smt import check_parsed_int_contract

        fixed = self._VULN.replace(
            "\ts.file.SetLinePosition",
            "\tif line < 1 || line > maxLineCol {\n\t\treturn\n\t}\n"
            "\ts.file.SetLinePosition",
        )
        assert not check_parsed_int_contract(fixed).narrowing_found

    def test_c_strtoul_index_flagged(self):
        from core.audit.condition_smt import check_parsed_int_contract

        src = (
            "static int parse(const char *p) {\n"
            "\tunsigned long idx;\n"
            "\tidx = strtoul(p, NULL, 10);\n"
            "\treturn table[idx];\n"
            "}\n"
        )
        r = check_parsed_int_contract(src)
        assert r.narrowing_found
        assert "index" in r.reasoning

    def test_unconsumed_parse_silent(self):
        from core.audit.condition_smt import check_parsed_int_contract

        src = (
            "func f(s string) {\n"
            "\tn, err := strconv.Atoi(s)\n"
            "\t_ = n\n"
            "\t_ = err\n"
            "}\n"
        )
        assert not check_parsed_int_contract(src).narrowing_found

    def test_consumer_width_binding_lands_in_reasoning(self):
        from core.audit.condition_smt import check_parsed_int_contract

        r = check_parsed_int_contract(
            self._VULN,
            consumer_widths={"SetLinePosition": 32},
        )
        assert r.narrowing_found
        assert "32-bit" in r.reasoning
        assert r.dest_width == 32

    def test_equality_check_does_not_discharge_contract(self):
        """`n == 0` bounds nothing — the contract stays undischarged."""
        from core.audit.condition_smt import check_parsed_int_contract

        src = (
            "func f(s string) {\n"
            "\tn, err := strconv.Atoi(s)\n"
            "\tif err != nil || n == 0 {\n"
            "\t\treturn\n"
            "\t}\n"
            "\tstore.Apply(n)\n"
            "}\n"
        )
        r = check_parsed_int_contract(src)
        assert r.narrowing_found
        assert "Apply" in r.reasoning


class TestParseWrapperDerivation:
    """Same-file parse wrappers: the stdlib idiom puts the strconv
    call one helper away from the consumer, so the checker learns the
    wrapper names from the file itself."""

    _FILE = (
        "package directive\n"
        "\n"
        "func readSuffixInt(text []byte) (int, int, bool) {\n"
        "\ti := lastColon(text)\n"
        "\tn, err := strconv.ParseUint(string(text[i+1:]), 10, 0)\n"
        "\treturn i + 1, int(n), err == nil\n"
        "}\n"
        "\n"
        "func unrelated(a int) int {\n"
        "\treturn a * 2\n"
        "}\n"
    )

    def test_wrapper_names_derived_from_file(self):
        from core.audit.condition_smt import derive_parse_wrappers

        w = derive_parse_wrappers(self._FILE)
        assert "readSuffixInt" in w
        assert "unrelated" not in w

    def test_c_wrapper_derived(self):
        from core.audit.condition_smt import derive_parse_wrappers

        src = (
            "static long read_num(const char *p)\n"
            "{\n"
            "\treturn strtol(p, NULL, 10);\n"
            "}\n"
        )
        assert "read_num" in derive_parse_wrappers(src)

    def test_wrapper_call_marks_values_parsed(self):
        from core.audit.condition_smt import check_parsed_int_contract

        consumer = (
            "func (s *Lexer) applyDirective(text []byte) {\n"
            "\ti, n, ok := readSuffixInt(text)\n"
            "\tif !ok {\n"
            "\t\treturn\n"
            "\t}\n"
            "\ts.file.SetLinePosition(i, n)\n"
            "}\n"
        )
        r = check_parsed_int_contract(
            consumer, parse_wrappers=frozenset({"readSuffixInt"}),
        )
        assert r.narrowing_found
        assert "SetLinePosition" in r.reasoning

    def test_no_wrappers_stays_silent(self):
        from core.audit.condition_smt import check_parsed_int_contract

        consumer = (
            "func (s *Lexer) applyDirective(text []byte) {\n"
            "\ti, n, ok := readSuffixInt(text)\n"
            "\ts.file.SetLinePosition(i, n)\n"
            "\t_ = ok\n"
            "}\n"
        )
        assert not check_parsed_int_contract(consumer).narrowing_found

    def test_alias_propagation_through_multi_assign(self):
        from core.audit.condition_smt import check_parsed_int_contract

        consumer = (
            "func (s *Lexer) applyDirective(text []byte) {\n"
            "\t_, n, ok := readSuffixInt(text)\n"
            "\t_, n2, ok2 := readSuffixInt(text[:4])\n"
            "\tvar row, col int\n"
            "\tif ok && ok2 {\n"
            "\t\trow, col = n2, n\n"
            "\t\tif col == 0 {\n"
            "\t\t\treturn\n"
            "\t\t}\n"
            "\t}\n"
            "\ts.file.SetLinePosition(row, col)\n"
            "}\n"
        )
        r = check_parsed_int_contract(
            consumer, parse_wrappers=frozenset({"readSuffixInt"}),
        )
        assert r.narrowing_found

    def test_range_checked_wrapper_value_silent(self):
        from core.audit.condition_smt import check_parsed_int_contract

        consumer = (
            "func (s *Lexer) applyDirective(text []byte) {\n"
            "\ti, n, ok := readSuffixInt(text)\n"
            "\tif !ok || n > maxVal || i > maxVal {\n"
            "\t\treturn\n"
            "\t}\n"
            "\ts.file.SetLinePosition(i, n)\n"
            "}\n"
        )
        r = check_parsed_int_contract(
            consumer, parse_wrappers=frozenset({"readSuffixInt"}),
        )
        assert not r.narrowing_found


class TestCastInReturnSuppression:
    """A bare type conversion inside a return statement is the
    producer idiom — the width contract belongs to the caller, so the
    helper itself stays silent."""

    def test_cast_in_return_is_silent(self):
        from core.audit.condition_smt import check_parsed_int_contract

        src = (
            "func readSuffixInt(text []byte) (int, int, bool) {\n"
            "\tn, err := strconv.ParseUint(string(text), 10, 0)\n"
            "\treturn 1, int(n), err == nil\n"
            "}\n"
        )
        assert not check_parsed_int_contract(src).narrowing_found

    def test_cast_mid_function_still_flagged(self):
        from core.audit.condition_smt import check_parsed_int_contract

        src = (
            "func setOwner(s string) {\n"
            "\tv, err := strconv.Atoi(s)\n"
            "\tif err != nil {\n"
            "\t\treturn\n"
            "\t}\n"
            "\tspec.UID = uint32(v)\n"
            "}\n"
        )
        r = check_parsed_int_contract(src)
        assert r.narrowing_found
        assert "uint32" in r.reasoning

    def test_real_callee_in_return_still_flagged(self):
        from core.audit.condition_smt import check_parsed_int_contract

        src = (
            "func lookup(s string) int {\n"
            "\tn, err := strconv.Atoi(s)\n"
            "\t_ = err\n"
            "\treturn resolve(n)\n"
            "}\n"
        )
        r = check_parsed_int_contract(src)
        assert r.narrowing_found
        assert "resolve" in r.reasoning


class TestNegationOverflow:
    """Broken-abs idiom on a text-derived value: -MinInt == MinInt, so
    a subsequent upper-bound cap is exactly the check the overflow
    defeats."""

    _VULN = (
        "func apply(s string) bool {\n"
        "\texp, err := strconv.ParseInt(s, 10, 64)\n"
        "\tif err != nil {\n"
        "\t\treturn false\n"
        "\t}\n"
        "\tn := exp\n"
        "\tif n < 0 {\n"
        "\t\tn = -n\n"
        "\t}\n"
        "\tif n > 1e6 {\n"
        "\t\treturn false\n"
        "\t}\n"
        "\tgrow(uint(n))\n"
        "\treturn true\n"
        "}\n"
    )

    def test_abs_idiom_without_min_guard_flagged(self):
        from core.audit.condition_smt import check_parsed_int_contract

        r = check_parsed_int_contract(self._VULN)
        assert r.narrowing_found
        assert r.dest_type == "negation"
        assert "MinInt" in r.reasoning

    def test_min_guard_silences(self):
        from core.audit.condition_smt import check_parsed_int_contract

        guarded = self._VULN.replace(
            "\tif n < 0 {\n",
            "\tif n == math.MinInt64 {\n\t\treturn false\n\t}\n"
            "\tif n < 0 {\n",
        )
        assert not check_parsed_int_contract(guarded).narrowing_found

    def test_c_llong_min_guard_silences(self):
        from core.audit.condition_smt import check_parsed_int_contract

        src = (
            "static int apply(const char *p) {\n"
            "\tlong long v;\n"
            "\tv = strtoll(p, NULL, 10);\n"
            "\tif (v == LLONG_MIN)\n"
            "\t\treturn -1;\n"
            "\tif (v < 0)\n"
            "\t\tv = -v;\n"
            "\tif (v > CAP)\n"
            "\t\treturn -1;\n"
            "\tgrow(v);\n"
            "\treturn 0;\n"
            "}\n"
        )
        assert not check_parsed_int_contract(src).narrowing_found


class TestConsumerWidthIndex:
    def test_go_signature_widths(self):
        from core.audit.condition_smt import build_consumer_width_index

        checklist = {
            "files": [{
                "path": "go/tokenpkg/pos.go",
                "items": [{
                    "name": "File.SetLinePosition",
                    "signature": (
                        "func (f *File) SetLinePosition(offset int, "
                        "filename string, line, column int32)"
                    ),
                }],
            }],
        }
        idx = build_consumer_width_index(checklist)
        assert idx["SetLinePosition"] == 32

    def test_missing_signature_skipped(self):
        from core.audit.condition_smt import build_consumer_width_index

        assert build_consumer_width_index(
            {"files": [{"items": [{"name": "f"}]}]},
        ) == {}


class TestSuccessReturnWhitespaceRun:
    def test_return_whitespace_run_is_fast(self, monkeypatch):
        """Hostile line where a ``return 0`` token is followed by a
        long whitespace RUN and no line end: with the tail spelled
        ``\\s*;?\\s*$`` two unbounded whitespace spans border the
        optional semicolon and the engine tries every split of the run
        between them — quadratic on a single return token. Folding the
        trailing span into the ``;``-gated group is linear.
        Both-direction bound: fast AND the real early success return
        (with and without ``;``) is still detected."""
        import time

        from core.audit.condition_smt import (
            _SUCCESS_RETURN_RE,
            check_auth_bypass,
        )
        # Measure the regex/checker path, independent of worker startup and
        # solver scheduling. Native worker contracts are tested separately.
        monkeypatch.setattr("core.audit.condition_smt._try_z3_auth_bypass", lambda *a, **kw: None)

        hostile = "    return 0" + " " * (1 << 18) + "x\n"
        source = (
            "static int foo_setattr(struct inode *inode)\n"
            "{\n"
            "    if (fast_path)\n"
            "        return 0;\n"
            + hostile
            + "    if (!capable(CAP_SYS_ADMIN))\n"
            "        return -EPERM;\n"
            "    return do_setattr(inode);\n"
            "}\n"
        )
        start = time.monotonic()
        result = check_auth_bypass(source)
        assert time.monotonic() - start < 5.0
        # The real early success return is still detected past the
        # hostile line.
        assert result.bypass_found
        # Tail semantics unchanged: optional semicolon, trailing
        # whitespace, plain-newline forms all still match; the
        # hostile non-terminated line does not.
        assert _SUCCESS_RETURN_RE.match("    return 0;")
        assert _SUCCESS_RETURN_RE.match("return EXIT_SUCCESS  ;  ")
        assert _SUCCESS_RETURN_RE.match("  return nil")
        assert not _SUCCESS_RETURN_RE.match("    return 0   x")


# ── Size-argument binding ───────────────────────────────────────────────


class TestSinkSizeIdentifiers:
    """Unit contract for the size-argument binding extractor."""

    def test_copy_sink_binds_third_argument(self):
        from core.audit.condition_smt import _sink_size_identifiers
        assert _sink_size_identifiers(
            "memcpy", ["dst", "src", "len"]) == ["len"]

    def test_sizeof_operand_is_not_a_variable(self):
        from core.audit.condition_smt import _sink_size_identifiers
        assert _sink_size_identifiers(
            "malloc", ["n * sizeof(struct item)"]) == ["n"]

    def test_calloc_binds_both_count_and_size(self):
        from core.audit.condition_smt import _sink_size_identifiers
        assert _sink_size_identifiers("calloc", ["n", "elem_size"]) == [
            "n", "elem_size"]

    def test_literal_size_binds_to_no_variables(self):
        from core.audit.condition_smt import _sink_size_identifiers
        assert _sink_size_identifiers("memcpy", ["dst", "src", "64"]) == []

    def test_missing_arguments_mean_binding_unknown(self):
        from core.audit.condition_smt import _sink_size_identifiers
        assert _sink_size_identifiers("memcpy", []) is None
        assert _sink_size_identifiers("memcpy", None) is None

    def test_short_call_shape_means_binding_unknown(self):
        from core.audit.condition_smt import _sink_size_identifiers
        assert _sink_size_identifiers("memcpy", ["dst", "src"]) is None

    def test_unmodelled_sink_means_binding_unknown(self):
        from core.audit.condition_smt import _sink_size_identifiers
        assert _sink_size_identifiers("system", ["cmd"]) is None


class TestSizeArgumentBinding:
    """Sufficiency proofs must bind to the sink's size argument.

    Bounding variables that never reach the sink's size argument used
    to mint "guard sufficient" / "cannot overflow" proofs, which the
    orchestrator consumes to skip decorative-guard verification."""

    def test_unrelated_guard_cannot_prove_alloc_safe(self):
        # Reproduced false conclusion: the guards bound retries and
        # attempts; the allocation sizes with n * size. The old pair
        # model multiplied the two GUARD variables and declared
        # "cannot overflow". The source-bound oracle goes further
        # than the binding-gap demotion: n and size are free, so it
        # PROVES the guard insufficient with a replayed wrap witness.
        pytest.importorskip("z3")
        g = _guard(
            "retries >= 0 && retries < MAXR && attempts >= 0 && attempts < MAXA",
            resolvable=True, concrete_values={"MAXR": "8", "MAXA": "3"},
        )
        sg = _sg("malloc", [g], sink_args=["n * size"])
        results = check_guard_sufficiency(sg)
        assert len(results) >= 1
        for r in results:
            assert r.feasible is True
            assert r.guard_sufficient is False
            assert r.oracle == "alloc-wrap/source-bound"
            assert r.witness and "n" in r.witness and "size" in r.witness

    def test_unrelated_guard_cannot_prove_copy_safe(self):
        # Old behaviour: retries ≤ 8 ≤ 256 → "guard sufficient" for a
        # memcpy whose length is len, never bounded anywhere.  The
        # source-bound oracle goes further than the binding-gap
        # demotion: len is free, so the guard is PROVABLY insufficient.
        pytest.importorskip("z3")
        g = _guard(
            "retries >= 0 && retries < MAXR",
            resolvable=True, concrete_values={"MAXR": "8"},
        )
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "len"])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        r = results[0]
        assert r.feasible is True
        assert r.guard_sufficient is False
        assert "len" in r.reasoning

    def test_insufficiency_grounded_in_size_variable_not_guard_var(self):
        # With a KNOWN binding, the insufficiency claim must be about
        # what memcpy actually copies — retries can be 4095 > 256, but
        # retries is not the copy length.  The verdict is True because
        # len is unconstrained, and the claim names len, not retries.
        pytest.importorskip("z3")
        g = _guard(
            "retries >= 0 && retries < MAXR",
            resolvable=True, concrete_values={"MAXR": "4096"},
        )
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "len"])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        r = results[0]
        assert r.feasible is True
        assert "copy length (len)" in r.reasoning
        assert "retries" not in r.reasoning
        # the witness overflows via len while retries still passes
        # the guard
        assert r.witness is not None
        assert r.witness["len"] % (1 << 64) > 256
        assert 0 <= r.witness["retries"] < 4096

    def test_bound_size_variable_keeps_sufficiency_proof(self):
        g = _guard(
            "len >= 0 && len < CAP",
            resolvable=True, concrete_values={"CAP": "128"},
        )
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "len"])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        assert results[0].feasible is False
        assert results[0].guard_sufficient is True

    def test_bound_size_variable_keeps_insufficiency_finding(self):
        g = _guard(
            "len >= 0 && len < CAP",
            resolvable=True, concrete_values={"CAP": "4096"},
        )
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "len"])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        assert results[0].feasible is True
        assert results[0].guard_sufficient is False

    def test_partially_bound_size_expression_overflow_found(self):
        # len is bounded but the copy length is len + hdr_len; a proof
        # over len alone says nothing about the sum.  The source-bound
        # oracle decides the SUM: hdr_len is free, so the guard is
        # provably insufficient — never "sufficient".
        pytest.importorskip("z3")
        g = _guard(
            "len >= 0 && len < CAP",
            resolvable=True, concrete_values={"CAP": "128"},
        )
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "len + hdr_len"])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        r = results[0]
        assert r.feasible is True
        assert r.oracle == "copy-bound/source-bound"
        assert r.witness is not None
        total = sum(
            r.witness[name] % (1 << 64) for name in ("len", "hdr_len")
        )
        assert total % (1 << 64) > 256

    def test_literal_size_argument_is_inconclusive(self):
        g = _guard(
            "len >= 0 && len < CAP",
            resolvable=True, concrete_values={"CAP": "128"},
        )
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "64"])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        assert results[0].feasible is None

    def test_unknown_binding_keeps_insufficiency_but_demotes_proof(self):
        # No sink_args captured (legacy extraction, unparsable call):
        # the insufficiency direction stays available as a hint, the
        # proof direction demotes to inconclusive.
        loose = _guard(
            "len < CAP", resolvable=True, concrete_values={"CAP": "4096"})
        tight = _guard(
            "len >= 0 && len < CAP",
            resolvable=True, concrete_values={"CAP": "128"},
        )
        flagged = check_guard_sufficiency(
            _sg("memcpy", [loose]), buffer_size=256)
        proved = check_guard_sufficiency(
            _sg("memcpy", [tight]), buffer_size=256)
        assert flagged[0].feasible is True
        assert proved[0].feasible is None
        assert "binding unknown" in proved[0].reasoning


class TestSizeExpressionParser:
    """Unit contract for the source-bound size-expression grammar."""

    def test_product_with_sizeof(self):
        from core.audit.condition_smt import _parse_size_expr
        assert _parse_size_expr("n * sizeof(struct item)") == (
            "mul", [("var", "n"), ("sizeof", "sizeof(struct item)")],
        )

    def test_sum_of_variables(self):
        from core.audit.condition_smt import _parse_size_expr
        assert _parse_size_expr("len + hdr_len") == (
            "add", [("var", "len"), ("var", "hdr_len")],
        )

    def test_parenthesised_sum_times_variable(self):
        from core.audit.condition_smt import _parse_size_expr
        assert _parse_size_expr("(a + b) * c") == (
            "mul", [("add", [("var", "a"), ("var", "b")]), ("var", "c")],
        )

    def test_hex_literal_with_suffix(self):
        from core.audit.condition_smt import _parse_size_expr
        assert _parse_size_expr("0x10u * count") == (
            "mul", [("const", 16), ("var", "count")],
        )

    def test_sizeof_whitespace_normalised(self):
        from core.audit.condition_smt import _parse_size_expr
        node = _parse_size_expr("n * sizeof( struct  item )")
        assert node == (
            "mul", [("var", "n"), ("sizeof", "sizeof( struct item )")],
        )

    def test_unsupported_arithmetic_declines(self):
        # Shifts, casts, subtraction, division and calls are outside
        # the grammar — the model must decline, never approximate.
        from core.audit.condition_smt import _parse_size_expr
        assert _parse_size_expr("n << 2") is None
        assert _parse_size_expr("(size_t)n * m") is None
        assert _parse_size_expr("n - 1") is None
        assert _parse_size_expr("total / 2") is None
        assert _parse_size_expr("f(n) * 2") is None

    def test_atom_budget_declines_pathological_expressions(self):
        from core.audit.condition_smt import _parse_size_expr
        assert _parse_size_expr("a * b * c * d * e * f") is not None
        assert _parse_size_expr("a * b * c * d * e * f * g") is None

    def test_degenerate_input_declines(self):
        from core.audit.condition_smt import _parse_size_expr
        assert _parse_size_expr("") is None
        assert _parse_size_expr("   ") is None
        assert _parse_size_expr("n +") is None
        assert _parse_size_expr("(a + b") is None
        assert _parse_size_expr(None) is None

    def test_literal_beyond_64_bits_declines(self):
        from core.audit.condition_smt import _parse_size_expr
        assert _parse_size_expr(str(1 << 64)) is None
        assert _parse_size_expr(str((1 << 64) - 1)) is not None

    def test_deep_nesting_declines_without_recursion_error(self):
        # The parser runs in the audit process itself; a hostile repo's
        # "((((…n…))))" must be declined by the token budget BEFORE the
        # recursive descent, never crash the audit with RecursionError.
        from core.audit.condition_smt import _parse_size_expr
        deep = "(" * 5000 + "n" + ")" * 5000
        assert _parse_size_expr(deep) is None

    def test_token_budget_boundary(self):
        from core.audit.condition_smt import (
            _SIZE_EXPR_MAX_TOKENS,
            _parse_size_expr,
        )
        depth_in = (_SIZE_EXPR_MAX_TOKENS - 1) // 2
        within = "(" * depth_in + "n" + ")" * depth_in
        over = "(" * (depth_in + 1) + "n" + ")" * (depth_in + 1)
        assert _parse_size_expr(within) == ("var", "n")
        assert _parse_size_expr(over) is None

    def test_hostile_sizeof_interior_declines(self):
        # The normalised sizeof text becomes witness keys and verdict
        # reasoning — control bytes and shell metacharacters from a
        # hostile repo must decline the whole expression.
        from core.audit.condition_smt import _parse_size_expr
        assert _parse_size_expr("n * sizeof(\x1b]0;x\x07struct t)") is None
        assert _parse_size_expr("n * sizeof($(id))") is None
        assert _parse_size_expr("n * sizeof(a\nb)") is None

    def test_benign_sizeof_interiors_still_parse(self):
        from core.audit.condition_smt import _parse_size_expr
        assert _parse_size_expr("n * sizeof(struct foo *)") is not None
        assert _parse_size_expr("n * sizeof(uint64_t[4])") is not None
        assert _parse_size_expr("n * sizeof(unsigned long long)") is not None


class TestSinkSizeExpressions:
    """Unit contract for the raw size-expression extractor."""

    def test_malloc_single_expression(self):
        from core.audit.condition_smt import _sink_size_expressions
        assert _sink_size_expressions(
            "malloc", ["n * sizeof(struct item)"],
        ) == ["n * sizeof(struct item)"]

    def test_calloc_both_arguments(self):
        from core.audit.condition_smt import _sink_size_expressions
        assert _sink_size_expressions(
            "calloc", ["n", "elem_size"]) == ["n", "elem_size"]

    def test_copy_sink_third_argument(self):
        from core.audit.condition_smt import _sink_size_expressions
        assert _sink_size_expressions(
            "memcpy", ["dst", "src", "len + 2"]) == ["len + 2"]

    def test_unknown_binding_semantics_match_identifiers(self):
        from core.audit.condition_smt import _sink_size_expressions
        assert _sink_size_expressions("memcpy", None) is None
        assert _sink_size_expressions("memcpy", []) is None
        assert _sink_size_expressions("memcpy", ["dst", "src"]) is None
        assert _sink_size_expressions("system", ["cmd"]) is None


class TestAllocWrapSourceBound:
    """Source-bound allocation-wrap oracle: both directions, with the
    false-proof shapes the pairwise model used to mint."""

    def test_wrap_witness_flags_insufficient_guard(self):
        # n <= 2**61 (two-sided) leaves room for n * 16 to reach
        # 2**64 — the guard is provably insufficient, witness-backed.
        pytest.importorskip("z3")
        g = _guard(
            "n >= 0 && n <= BIG",
            resolvable=True, concrete_values={"BIG": str(1 << 61)},
        )
        sg = _sg("malloc", [g], sink_args=["n * 16"])
        results = check_guard_sufficiency(sg)
        assert len(results) == 1
        r = results[0]
        assert r.feasible is True
        assert r.oracle == "alloc-wrap/source-bound"
        assert r.witness and "n" in r.witness
        # the witness must actually wrap: unsigned n * 16 >= 2**64
        assert (r.witness["n"] % (1 << 64)) * 16 >= (1 << 64)

    def test_bounded_arithmetic_proves_guard_sufficient(self):
        pytest.importorskip("z3")
        g = _guard(
            "n >= 0 && n < CAP",
            resolvable=True, concrete_values={"CAP": "1000"},
        )
        sg = _sg("malloc", [g], sink_args=["n * 16"])
        results = check_guard_sufficiency(sg)
        assert len(results) == 1
        r = results[0]
        assert r.feasible is False
        assert r.guard_sufficient is True
        assert r.oracle == "alloc-wrap/source-bound"
        assert "cannot reach 2**64" in r.reasoning

    def test_one_sided_guard_stays_insufficient(self):
        # ``n <= 1000`` without a lower bound admits negative n, whose
        # unsigned reading is huge — the wrap stays possible.
        pytest.importorskip("z3")
        g = _guard(
            "n <= CAP", resolvable=True, concrete_values={"CAP": "1000"},
        )
        sg = _sg("malloc", [g], sink_args=["n * 16"])
        results = check_guard_sufficiency(sg)
        assert results[0].feasible is True

    def test_triple_product_wrap_not_missed(self):
        # RED-CHECK SHAPE: n, m, k each <= 2**22; every PAIR product
        # stays under 2**44, so the pairwise model proved "cannot
        # overflow" — but n * m * k reaches 2**66.  The source-bound
        # encoding of the full expression finds the wrap.
        pytest.importorskip("z3")
        bound = str(1 << 22)
        g = _guard(
            "n >= 0 && n <= B && m >= 0 && m <= B && k >= 0 && k <= B",
            resolvable=True, concrete_values={"B": bound},
        )
        sg = _sg("malloc", [g], sink_args=["n * m * k"])
        results = check_guard_sufficiency(sg)
        assert len(results) == 1
        r = results[0]
        assert r.feasible is True
        assert r.oracle == "alloc-wrap/source-bound"
        assert r.witness is not None

    def test_calloc_bounded_product_proves_sufficient(self):
        pytest.importorskip("z3")
        g = _guard(
            "n >= 0 && n < CAP && m >= 0 && m < CAP",
            resolvable=True, concrete_values={"CAP": "4096"},
        )
        sg = _sg("calloc", [g], sink_args=["n", "m"])
        results = check_guard_sufficiency(sg)
        assert results[0].feasible is False
        assert results[0].oracle == "alloc-wrap/source-bound"

    def test_calloc_wide_bounds_wrap(self):
        pytest.importorskip("z3")
        g = _guard(
            "n >= 0 && n <= B && m >= 0 && m <= B",
            resolvable=True, concrete_values={"B": str(1 << 40)},
        )
        sg = _sg("calloc", [g], sink_args=["n", "m"])
        results = check_guard_sufficiency(sg)
        assert results[0].feasible is True
        assert results[0].oracle == "alloc-wrap/source-bound"

    def test_sizeof_proof_states_its_assumption(self):
        pytest.importorskip("z3")
        g = _guard(
            "n >= 0 && n < CAP",
            resolvable=True, concrete_values={"CAP": "1000"},
        )
        sg = _sg("malloc", [g], sink_args=["n * sizeof(struct item)"])
        results = check_guard_sufficiency(sg)
        r = results[0]
        assert r.feasible is False
        assert r.oracle == "alloc-wrap/source-bound"
        assert "sizeof terms assumed" in r.reasoning

    def test_sum_shape_decided_exactly(self):
        pytest.importorskip("z3")
        g = _guard(
            "len >= 0 && len <= CAP && hdr >= 0 && hdr <= CAP",
            resolvable=True, concrete_values={"CAP": "100"},
        )
        sg = _sg("malloc", [g], sink_args=["len + hdr"])
        results = check_guard_sufficiency(sg)
        assert results[0].feasible is False
        assert results[0].oracle == "alloc-wrap/source-bound"

    def test_exact_wrap_boundary_is_two_sided(self):
        # The wrap question is "can the product reach 2**64": a bound
        # admitting exactly 2**64 is a wrap (the sink receives 0), one
        # stopping at 2**64 - 16 is a proof.  Pins the Extract-based
        # query at its exact boundary.
        pytest.importorskip("z3")
        at = _guard(
            "n >= 0 && n <= B",
            resolvable=True, concrete_values={"B": str(1 << 60)},
        )
        results = check_guard_sufficiency(_sg(
            "malloc", [at], sink_args=["n * 16"]))
        assert results[0].feasible is True
        assert results[0].witness is not None
        assert (results[0].witness["n"] % (1 << 64)) * 16 >= (1 << 64)

        under = _guard(
            "n >= 0 && n <= B",
            resolvable=True, concrete_values={"B": str((1 << 60) - 1)},
        )
        results = check_guard_sufficiency(_sg(
            "malloc", [under], sink_args=["n * 16"]))
        assert results[0].feasible is False
        assert results[0].oracle == "alloc-wrap/source-bound"

    def test_single_term_size_has_no_wrap_question(self):
        # malloc(n): a lone 64-bit value never reaches 2**64 — the
        # oracle answers inconclusive, same consumer behaviour as the
        # pre-oracle model (no vacuous proof either way).
        pytest.importorskip("z3")
        g = _guard(
            "n >= 0 && n < CAP",
            resolvable=True, concrete_values={"CAP": "1000"},
        )
        sg = _sg("malloc", [g], sink_args=["n"])
        results = check_guard_sufficiency(sg)
        assert results[0].feasible is None
        assert results[0].guard_sufficient is None

    def test_unparsed_expression_demotes_pairwise_proof(self):
        # RED-CHECK SHAPE: the size argument carries a cast the
        # grammar declines.  The pairwise model used to bound the two
        # guard variables and mint "cannot overflow" — a proof about
        # arithmetic it never saw.  Expressions present but unparsed
        # demote that proof to inconclusive.
        pytest.importorskip("z3")
        g = _guard(
            "n >= 0 && n < CAP && m >= 0 && m < CAP",
            resolvable=True, concrete_values={"CAP": "100"},
        )
        sg = _sg("malloc", [g], sink_args=["(size_t)n * m"])
        results = check_guard_sufficiency(sg)
        r = results[0]
        assert r.feasible is None
        assert r.guard_sufficient is None
        assert "outside the supported arithmetic model" in r.reasoning

    def test_unbound_expression_variable_blocks_proof(self):
        # The expression parses but ``size`` is never guard-bounded:
        # UNSAT cannot happen with a free 64-bit variable here, but a
        # bounded-times-free shape where the free var is multiplied by
        # zero-able terms must not mint a proof from the gap path.
        pytest.importorskip("z3")
        from core.audit.condition_smt import (
            BoundsConstraint,
            _z3_alloc_overflow_check,
        )
        out = _z3_alloc_overflow_check(
            [
                BoundsConstraint("n", ">=", 0, "n >= 0"),
                BoundsConstraint("n", "<=", 100, "n <= 100"),
            ],
            ["n", "size"],
            ["n * 0 * size"],
        )
        assert out[0] is not False
        if out[0] is None:
            assert "unconstrained" in out[1]

    def test_oracle_tag_in_to_dict(self):
        pytest.importorskip("z3")
        g = _guard(
            "n >= 0 && n < CAP",
            resolvable=True, concrete_values={"CAP": "1000"},
        )
        sg = _sg("malloc", [g], sink_args=["n * 16"])
        d = check_guard_sufficiency(sg)[0].to_dict()
        assert d.get("oracle") == "alloc-wrap/source-bound"


class TestCopyBoundSourceBound:
    """Source-bound copy-length oracle: the sink's size expression is
    decided as the arithmetic it computes, not variable by variable."""

    def test_sum_overflow_not_missed(self):
        # RED-CHECK SHAPE: len and hdr each fit the 128-byte buffer on
        # their own, so the per-variable model proved the guard
        # sufficient — but the sink copies len + hdr, which reaches
        # 200.  The source-bound encoding finds the overflow.
        pytest.importorskip("z3")
        g = _guard(
            "len >= 0 && len <= CAP && hdr >= 0 && hdr <= CAP",
            resolvable=True, concrete_values={"CAP": "100"},
        )
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "len + hdr"])
        results = check_guard_sufficiency(sg, buffer_size=128)
        assert len(results) == 1
        r = results[0]
        assert r.feasible is True
        assert r.guard_sufficient is False
        assert r.oracle == "copy-bound/source-bound"
        assert r.witness is not None
        # the witness sum must actually exceed the buffer
        total = sum(
            r.witness[name] % (1 << 64) for name in ("len", "hdr")
        )
        assert total > 128

    def test_sum_within_capacity_proves_sufficient(self):
        pytest.importorskip("z3")
        g = _guard(
            "len >= 0 && len <= CAP && hdr >= 0 && hdr <= CAP",
            resolvable=True, concrete_values={"CAP": "100"},
        )
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "len + hdr"])
        results = check_guard_sufficiency(sg, buffer_size=256)
        r = results[0]
        assert r.feasible is False
        assert r.guard_sufficient is True
        assert r.oracle == "copy-bound/source-bound"

    def test_wrapped_product_is_wrap_truthful(self):
        # len * hdr can wrap modulo 2**64; the sink receives the
        # WRAPPED value, and the oracle reasons about that value — a
        # wrapped-small copy length is not reported as huge.
        pytest.importorskip("z3")
        g = _guard(
            "len >= 0 && len <= B && hdr >= 0 && hdr <= B",
            resolvable=True, concrete_values={"B": str(1 << 40)},
        )
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "len * hdr"])
        results = check_guard_sufficiency(sg, buffer_size=128)
        r = results[0]
        assert r.feasible is True
        assert r.oracle == "copy-bound/source-bound"

    def test_strncat_never_gets_a_sufficiency_proof(self):
        # RED-CHECK SHAPE: n in [0, 100] against a 128-byte buffer
        # used to prove "guard sufficient" — but strncat writes
        # strlen(dst) + n + 1 bytes and the destination's existing
        # content is outside the model.
        pytest.importorskip("z3")
        g = _guard(
            "n >= 0 && n <= CAP",
            resolvable=True, concrete_values={"CAP": "100"},
        )
        sg = _sg("strncat", [g], sink_args=["dst", "src", "n"])
        results = check_guard_sufficiency(sg, buffer_size=128)
        r = results[0]
        assert r.feasible is None
        assert r.guard_sufficient is None
        assert "destination content" in r.reasoning

    def test_strncat_terminator_counts_against_capacity(self):
        # n can be exactly the buffer size; strncat's terminator makes
        # the write n + 1 — overflow by one byte.
        pytest.importorskip("z3")
        g = _guard(
            "n >= 0 && n <= CAP",
            resolvable=True, concrete_values={"CAP": "128"},
        )
        sg = _sg("strncat", [g], sink_args=["dst", "src", "n"])
        results = check_guard_sufficiency(sg, buffer_size=128)
        r = results[0]
        assert r.feasible is True
        assert r.oracle == "copy-bound/source-bound"
        assert "terminator" in r.reasoning

    def test_bare_variable_expression_keeps_proof_and_gains_tag(self):
        pytest.importorskip("z3")
        g = _guard(
            "len >= 0 && len < CAP",
            resolvable=True, concrete_values={"CAP": "128"},
        )
        sg = _sg("memcpy", [g], sink_args=["dst", "src", "len"])
        results = check_guard_sufficiency(sg, buffer_size=256)
        r = results[0]
        assert r.feasible is False
        assert r.oracle == "copy-bound/source-bound"

    def test_unparsed_expression_demotes_per_variable_proof(self):
        # RED-CHECK SHAPE: a cast the grammar declines; the
        # per-variable model used to prove sufficiency from bounds on
        # len and hdr while the actual expression was never modelled.
        pytest.importorskip("z3")
        g = _guard(
            "len >= 0 && len <= CAP && hdr >= 0 && hdr <= CAP",
            resolvable=True, concrete_values={"CAP": "100"},
        )
        sg = _sg(
            "memcpy", [g], sink_args=["dst", "src", "(size_t)len + hdr"],
        )
        results = check_guard_sufficiency(sg, buffer_size=128)
        r = results[0]
        assert r.feasible is None
        assert r.guard_sufficient is None
        assert "outside the supported arithmetic model" in r.reasoning

    def test_insufficiency_hint_survives_unparsed_expression(self):
        # The True direction stays available on unparsed expressions:
        # a bound of 4096 on a size-argument variable against a
        # 128-byte buffer is still an insufficiency signal.
        pytest.importorskip("z3")
        g = _guard(
            "len >= 0 && len <= CAP",
            resolvable=True, concrete_values={"CAP": "4096"},
        )
        sg = _sg(
            "memcpy", [g], sink_args=["dst", "src", "(size_t)len + hdr"],
        )
        results = check_guard_sufficiency(sg, buffer_size=128)
        assert results[0].feasible is True

    def test_sizeof_scaled_copy_decided_with_stated_assumption(self):
        pytest.importorskip("z3")
        g = _guard(
            "count >= 0 && count <= CAP",
            resolvable=True, concrete_values={"CAP": "4"},
        )
        sg = _sg(
            "memcpy", [g],
            sink_args=["dst", "src", "count * sizeof(struct item)"],
        )
        results = check_guard_sufficiency(sg, buffer_size=128)
        r = results[0]
        # sizeof may be anything in [1, 2**32): 4 * sizeof can exceed
        # 128, so the guard is insufficient under the stated assumption.
        assert r.feasible is True
        assert r.oracle == "copy-bound/source-bound"

    def test_fallback_strncat_never_proves(self):
        from core.audit.condition_smt import (
            BoundsConstraint,
            _arithmetic_check,
        )
        g = _guard("n <= CAP", resolvable=True, concrete_values={"CAP": "100"})
        out = _arithmetic_check(
            [
                BoundsConstraint("n", ">=", 0, "n >= 0"),
                BoundsConstraint("n", "<=", 100, "n <= 100"),
            ],
            g, 128, "strncat", ["n"], ["n"],
        )
        assert out.feasible is None
        assert "destination content" in out.reasoning

    def test_fallback_proof_requires_bare_variable_expression(self):
        from core.audit.condition_smt import (
            BoundsConstraint,
            _arithmetic_check,
        )
        g = _guard(
            "len <= CAP && hdr <= CAP",
            resolvable=True, concrete_values={"CAP": "100"},
        )
        constraints = [
            BoundsConstraint("len", ">=", 0, "len >= 0"),
            BoundsConstraint("len", "<=", 100, "len <= 100"),
            BoundsConstraint("hdr", ">=", 0, "hdr >= 0"),
            BoundsConstraint("hdr", "<=", 100, "hdr <= 100"),
        ]
        summed = _arithmetic_check(
            constraints, g, 128, "memcpy", ["len", "hdr"], ["len + hdr"],
        )
        assert summed.feasible is None
        assert "outside the supported arithmetic model" in summed.reasoning
        bare = _arithmetic_check(
            constraints[:2], g, 128, "memcpy", ["len"], ["len"],
        )
        assert bare.feasible is False


class TestVerdictTupleFromChild:
    """Child-JSON protocol: the optional 4th element is the oracle tag.

    A malformed tag must degrade to the untagged 3-tuple with the SAME
    verdict — never flip a verdict, never reject the whole result.
    """

    def test_tagged_tuple_round_trips(self):
        from core.audit.condition_smt import _verdict_tuple_from_child
        out = _verdict_tuple_from_child(
            [True, "wrap witness", {"n": 1}, "alloc-wrap/source-bound"])
        assert out == (
            True, "wrap witness", {"n": 1}, "alloc-wrap/source-bound")

    def test_malformed_tag_degrades_to_untagged_same_verdict(self):
        from core.audit.condition_smt import _verdict_tuple_from_child
        for bad_tag in (7, None, "", ["x"], {"t": 1}):
            out = _verdict_tuple_from_child(
                [False, "proof", None, bad_tag])
            assert out == (False, "proof", None)

    def test_wrong_arity_rejected(self):
        from core.audit.condition_smt import _verdict_tuple_from_child
        assert _verdict_tuple_from_child([True, "r"]) is None
        assert _verdict_tuple_from_child(
            [True, "r", None, "tag", "extra"]) is None

    def test_non_bool_verdict_rejected_even_with_tag(self):
        from core.audit.condition_smt import _verdict_tuple_from_child
        assert _verdict_tuple_from_child(
            ["yes", "r", None, "alloc-wrap/source-bound"]) is None
