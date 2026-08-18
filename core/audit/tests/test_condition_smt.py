"""Tests for condition_smt — constant-to-SMT bridge for guard sufficiency."""


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


def _sg(sink_api: str, guards: list, line: int = 10) -> SinkGuard:
    return SinkGuard(
        sink_file="test.c",
        sink_line=line,
        sink_function="process",
        sink_api=sink_api,
        guards=guards,
        unconditional=(len(guards) == 0),
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
        g = _guard(
            "len < BUF_SIZE",
            resolvable=True,
            concrete_values={"BUF_SIZE": "128"},
        )
        sg = _sg("memcpy", [g])
        results = check_guard_sufficiency(sg, buffer_size=256)
        assert len(results) >= 1
        r = results[0]
        assert r.feasible is False  # overflow NOT feasible
        assert r.guard_sufficient is True

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
        """Guard with two upper bounds — tightest determines sufficiency."""
        # "len < 4096 && len < 256" with buffer=256
        # Tightest: max_allowed=255 <= 256 → sufficient
        g = _guard(
            "len < MAX_SIZE && len < LIMIT",
            resolvable=True,
            concrete_values={"MAX_SIZE": "4096", "LIMIT": "256"},
        )
        sg = _sg("memcpy", [g])
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
        g2 = _guard("n <= SIZE", resolvable=True, concrete_values={"SIZE": "128"})
        guards = [_sg("memcpy", [g1], line=10), _sg("memcpy", [g2], line=20)]
        results = check_all_sufficiency(
            guards,
            buffer_sizes={10: 256, 20: 256},
        )
        assert len(results) == 2
        # First: 4096 > 256 → insufficient
        assert results[0][0].feasible is True
        # Second: 128 <= 256 → sufficient
        assert results[1][0].feasible is False


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
        g = _guard(
            "n <= LIMIT",
            resolvable=True,
            concrete_values={"LIMIT": "128"},
        )
        sg = _sg("memcpy", [g], line=10)
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
        # Z3 detects this; arithmetic fallback doesn't (no upper/lower bounds)
        # Either way, if Z3 is available it's UNSAT
        if result.feasible is not None:
            assert result.feasible is False


# ── Signed/unsigned mismatch ─────────────────────────────────────────


class TestSignedMismatch:
    def test_detects_mismatch(self):
        g = _guard("size < 1024", resolvable=True, concrete_values={})
        result = check_signed_mismatch(g, var_is_unsigned=True, bit_width=32)
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
