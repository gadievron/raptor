"""Public-API-boundary guard channel.

Observed field failure: caller-contract hypotheses (NULL host from an
external API consumer; negative outl bypassing bio_read_intern's
guard; kernel notification semantics) were unmappable to any tool —
flow tools reported "no in-tree triggering path" and the verdicts
died speculative. The channel checks the asserted obligation at every
in-repo call site instead: all-guarded → refuted-with-receipts, a
concrete unguarded site → confirmed-with-receipt, external-only
callers / external contracts → inconclusive-with-reason. Hermetic —
no LLM, no subprocesses.
"""

from __future__ import annotations

from core.audit.api_boundary import (
    api_boundary_applicable,
    extract_contract,
    is_caller_conditional_hypothesis,
    is_caller_contract_hypothesis,
    is_single_call_hypothesis,
    parse_param_names,
    run_api_boundary_check,
)

DEFINITION = """
int bio_lookup_ex(const char *host, int port, int family)
{
    if (family == AF_UNIX && host == NULL)
        return 0;
    return do_lookup(host, port, family);
}
"""


def _write_target(tmp_path, callers_c: str):
    (tmp_path / "lookup.c").write_text(DEFINITION)
    (tmp_path / "callers.c").write_text(callers_c)
    return tmp_path


class TestHypothesisShape:
    def test_caller_contract_shapes_detected(self):
        assert is_caller_contract_hypothesis(
            "NULL host is only reachable from external API consumers",
        )
        assert is_caller_contract_hypothesis(
            "requires a caller to pass negative outl, bypassing "
            "bio_read_intern's guard",
        )
        assert not is_caller_contract_hypothesis(
            "unchecked memcpy of the notification buffer overflows snp",
        )


class TestContractExtraction:
    PARAMS = ("host", "port", "family")

    def test_null_parameter_contract(self):
        c = extract_contract(
            "a NULL host with AF_UNIX reaches the unchecked branch; "
            "callers must never pass NULL host",
            self.PARAMS,
        )
        assert c is not None and c.kind == "null"
        assert c.param == "host" and c.param_index == 0

    def test_negative_parameter_contract(self):
        c = extract_contract(
            "negative port bypasses the size check in callers",
            self.PARAMS,
        )
        assert c is not None and c.kind == "negative"
        assert c.param == "port" and c.param_index == 1

    def test_external_environment_contract(self):
        c = extract_contract(
            "the kernel may truncate the notification; callers must "
            "handle short reads",
            self.PARAMS,
        )
        assert c is not None and c.kind == "external"

    def test_unbindable_contract_is_none(self):
        assert extract_contract("callers must be careful", self.PARAMS) is None


class TestParamParsing:
    def test_parses_definition_params(self):
        assert parse_param_names(DEFINITION, "bio_lookup_ex") == [
            "host", "port", "family",
        ]

    def test_ignores_prototypes(self):
        src = (
            "int f(const char *host, int port);\n"
            "int f(const char *h2, int p2)\n{\n    return 0;\n}\n"
        )
        assert parse_param_names(src, "f") == ["h2", "p2"]


HYP_NULL = (
    "callers must never pass NULL host; the AF_UNIX branch "
    "dereferences it"
)


class TestVerdicts:
    def test_window_guard_receipts_hint_but_cannot_refute(self, tmp_path):
        # The per-site 'guarded' verdict for site a comes from a
        # regex over a text window above the call — no dominance/
        # branch proof (a check in a sibling branch matches just the
        # same). A lexical receipt may HINT, never refute: the
        # all-guarded outcome downgrades to inconclusive.
        target = _write_target(tmp_path, """
int a(const char *name) {
    if (name == NULL)
        return -1;
    return bio_lookup_ex(name, 80, 0);
}
int b(void) {
    return bio_lookup_ex("localhost", 80, 0);
}
""")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert res.outcome == "inconclusive", res.to_dict()
        assert "lexical" in res.reason
        assert len(res.sites) == 2
        assert all(s.verdict == "guarded" for s in res.sites)
        assert all(s.evidence for s in res.sites), (
            "the hint must still carry per-site guard receipts"
        )
        assert {s.grade for s in res.sites} == {"lexical", "structural"}

    def test_all_sites_structurally_guarded_still_refutes(self, tmp_path):
        # Argument-shape receipts are sound (a string literal / an
        # address-of expression cannot be NULL) — structural-only
        # guard sets keep the refutation.
        target = _write_target(tmp_path, """
int b(void) {
    return bio_lookup_ex("localhost", 80, 0);
}
int c(struct addr *r) {
    return bio_lookup_ex(&r->name[0], 80, 0);
}
""")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert res.outcome == "refuted", res.to_dict()
        assert all(s.grade == "structural" for s in res.sites)

    def test_comment_guard_text_is_not_a_guard(self, tmp_path):
        # Regression PoC: '/* if (!host) never happens */' above the
        # call matched the NULL-guard regex and forged the receipt.
        target = _write_target(tmp_path, """
int a(const char *host) {
    /* if (!host) callers handled elsewhere */
    return bio_lookup_ex(host, 80, 0);
}
""")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert res.outcome == "inconclusive", res.to_dict()
        undecided = [s for s in res.sites if s.verdict == "undecided"]
        assert undecided, "comment text must not read as a guard"

    def test_call_in_comment_is_not_a_call_site(self, tmp_path):
        target = _write_target(tmp_path, """
/* legacy: bio_lookup_ex(NULL, 0, 0) was removed in v2 */
int b(void) {
    return bio_lookup_ex("localhost", 80, 0);
}
""")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert len(res.sites) == 1, [s.to_dict() for s in res.sites]
        assert res.outcome == "refuted", res.to_dict()

    def test_concrete_unguarded_site_confirms(self, tmp_path):
        target = _write_target(tmp_path, """
int careless(void) {
    return bio_lookup_ex(NULL, 80, 2);
}
""")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert res.outcome == "confirmed", res.to_dict()
        assert "callers.c" in res.reason
        unguarded = [s for s in res.sites if s.verdict == "unguarded"]
        assert unguarded and "NULL" in unguarded[0].evidence

    def test_external_only_callers_inconclusive(self, tmp_path):
        (tmp_path / "lookup.c").write_text(DEFINITION)
        res = run_api_boundary_check(
            tmp_path, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert res.outcome == "inconclusive"
        assert "external-only callers" in res.reason

    def test_undecided_site_gates_to_inconclusive(self, tmp_path):
        # `name` flows in with no visible guard: never guess.
        target = _write_target(tmp_path, """
int passthrough(const char *name) {
    return bio_lookup_ex(name, 80, 0);
}
""")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert res.outcome == "inconclusive", res.to_dict()
        assert any(s.verdict == "undecided" for s in res.sites)

    def test_kernel_contract_gets_external_receipt(self, tmp_path):
        target = _write_target(tmp_path, "\n")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex",
            "the kernel may deliver a truncated notification; callers "
            "must tolerate short reads",
        )
        assert res.outcome == "inconclusive"
        assert "external contract" in res.reason

    def test_negative_contract_checks_sign_guards(self, tmp_path):
        target = _write_target(tmp_path, """
int checked(int n) {
    if (n < 0)
        return -1;
    return bio_lookup_ex("x", n, 0);
}
int unsigned_source(void) {
    return bio_lookup_ex("x", sizeof(int), 0);
}
""")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex",
            "callers must never pass negative port",
        )
        # The sign check for `checked` is a window-regex hit (lexical
        # grade) — it hints, so the outcome is inconclusive rather
        # than refuted; the sites still carry guarded receipts.
        assert res.outcome == "inconclusive", res.to_dict()
        assert all(s.verdict == "guarded" for s in res.sites)
        assert any(s.grade == "lexical" for s in res.sites)

    def test_definition_span_not_counted_as_call_site(self, tmp_path):
        (tmp_path / "lookup.c").write_text(DEFINITION)
        (tmp_path / "user.c").write_text(
            "int u(void) { return bio_lookup_ex(NULL, 1, 2); }\n",
        )
        res = run_api_boundary_check(
            tmp_path, "lookup.c", "bio_lookup_ex", HYP_NULL,
            def_span=(1, 8),
        )
        files = {s.file for s in res.sites}
        assert files == {"user.c"}


def _overlong_call(callee: str) -> str:
    # One call whose argument list overflows the _balanced_span
    # window — trivially plantable in a hostile repo.
    args = ", ".join(f"arg_{i:04d}" for i in range(600))
    return (
        f"void evil_caller(void) {{\n    {callee}(NULL, {args});\n}}\n"
    )


class TestSpanBoundHonesty:
    """A truncated enumeration must never claim completeness.

    The span bound drops call-shaped matches whose argument list
    stays unbalanced within the window; that drop is an honesty
    event, never silent — a refutation over the surviving sites is a
    hint, not a receipt.
    """

    GUARDED = """
int b(void) {
    return bio_lookup_ex("localhost", 80, 0);
}
"""

    def test_span_capped_site_vetoes_enumeration_complete(
        self, tmp_path,
    ):
        target = _write_target(
            tmp_path, self.GUARDED + _overlong_call("bio_lookup_ex"),
        )
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        # The surviving sites are guarded, so the outcome may refute —
        # but never with a completeness stamp over a dropped match.
        assert not res.enumeration_complete, res.to_dict()
        assert any(
            "span bound" in n for n in res.enumeration_notes
        ), res.enumeration_notes

    def test_control_without_overlong_call_earns_completeness(
        self, tmp_path,
    ):
        # Two-direction pin: the honesty flag fires only on a bound
        # hit — the clean shape still earns its completeness receipt.
        target = _write_target(tmp_path, self.GUARDED)
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert res.outcome == "refuted", res.to_dict()
        assert res.enumeration_complete, res.to_dict()

    def test_overlong_call_cannot_blind_param_parsing(self):
        # A planted over-long CALL before the definition must not
        # stop the parser from reaching the real definition.
        src = _overlong_call("bio_lookup_ex") + DEFINITION
        assert parse_param_names(src, "bio_lookup_ex") == [
            "host", "port", "family",
        ]

    def test_overlong_definition_params_bind_nothing(self):
        # A definition whose own parameter list overflows the span
        # binds no parameters (the check abstains downstream) —
        # never a wrong binding.
        params = ", ".join(f"int arg_{i:04d}" for i in range(600))
        src = f"int f({params})\n{{\n    return 0;\n}}\n"
        assert parse_param_names(src, "f") == []


# Field exemplar (caller-proof FP family): the review asserts a
# misuse contract that every actual call site upholds.
HYP_SINGLE_CALL = (
    "Double free of b if a caller invokes bitmap_free twice on the "
    "same pointer (free(b) has no idempotence guard)"
)

BITMAP_DEF = """\
void bitmap_free(struct bitmap *b)
{
    if (b == NULL)
        return;
    free(b->d);
    free(b);
}
"""


def _bitmap_target(tmp_path, callers_c: str):
    (tmp_path / "bitmap.c").write_text(BITMAP_DEF)
    (tmp_path / "callers.c").write_text(callers_c)
    return tmp_path


def _run_single_call(target, hyp=HYP_SINGLE_CALL):
    return run_api_boundary_check(
        target, "bitmap.c", "bitmap_free", hyp, def_span=(1, 7),
    )


class TestSingleCallClassifier:
    def test_caller_conditioned_shapes_match(self):
        assert is_single_call_hypothesis(HYP_SINGLE_CALL)
        assert is_single_call_hypothesis(
            "crashes if called twice on the same context",
        )
        assert is_single_call_hypothesis(
            "callers must call it exactly once",
        )
        assert is_single_call_hypothesis(
            "free has no idempotence guard; not idempotent",
        )

    def test_idempotence_safety_assertions_do_not_match(self):
        # Only NEGATED idempotence vocabulary is a caller contract —
        # "is idempotent" is a safety assertion.
        assert not is_single_call_hypothesis(
            "the free is idempotent by design and safe to retry",
        )
        assert not is_single_call_hypothesis(
            "idempotency is guaranteed by the NULL check at entry",
        )

    def test_gap_tokens_are_identifier_shaped(self):
        # The conditional-gap token class admits identifier-ish
        # tokens (p->next, *ptr, re-invoked) but not arbitrary
        # punctuation-joined expressions.
        assert is_single_call_hypothesis(
            "double free if p->owner frees it again",
        )
        assert is_single_call_hypothesis(
            "crashes when *ctx is re-invoked twice",
        )
        assert not is_single_call_hypothesis(
            "if x=y invokes it twice",
        )
        assert not is_single_call_hypothesis(
            "when a/b calls it again",
        )

    def test_declarative_in_body_claims_do_not_match(self):
        # An in-body double-call is a defect INSIDE the reviewed
        # function; adjudicating its callers tests the wrong
        # mechanism and must not dispatch.
        assert not is_single_call_hypothesis(
            "free(p) is called twice on the error path at lines 61 "
            "and 72",
        )
        assert not is_single_call_hypothesis(
            "double free of ptr: freed at line 10 and at line 30",
        )


class TestCallerConditionalDispatch:
    def test_conditional_cwe_dispatches_with_conditional_phrasing(self):
        assert api_boundary_applicable("CWE-415", HYP_SINGLE_CALL)
        assert api_boundary_applicable(
            "CWE-476",
            "ssh->chanctxt is NULL when called before "
            "channel_init_channels",
        )
        assert api_boundary_applicable(
            "CWE-416",
            "use after free if the caller reuses ctx after teardown",
        )

    def test_conditional_cwe_declines_in_body_phrasing(self):
        assert not api_boundary_applicable(
            "CWE-416", "use after free of buf in the parse loop",
        )
        assert not api_boundary_applicable(
            "CWE-476", "p is dereferenced before the null check",
        )
        assert not api_boundary_applicable("CWE-415", "")

    def test_cwe_345_stays_unconditional(self):
        assert api_boundary_applicable("CWE-345")
        assert api_boundary_applicable("CWE-345", "any phrasing")

    def test_caller_conditional_union_classifier(self):
        assert is_caller_conditional_hypothesis(HYP_SINGLE_CALL)
        assert is_caller_conditional_hypothesis(
            "NULL host is only reachable from external API consumers",
        )
        assert not is_caller_conditional_hypothesis(
            "unchecked memcpy overflows the destination buffer",
        )


class TestSingleCallContractExtraction:
    def test_binds_to_named_parameter(self):
        c = extract_contract(HYP_SINGLE_CALL, ["b"])
        assert c is not None and c.kind == "single_call"
        assert c.param == "b" and c.param_index == 0

    def test_binds_to_sole_parameter_when_unnamed(self):
        c = extract_contract(
            "crashes if called twice on the same context", ["ctx"],
        )
        assert c is not None and c.kind == "single_call"
        assert c.param == "ctx"

    def test_multi_param_unnamed_declines_to_bind(self):
        assert extract_contract(
            "crashes if called twice", ["a", "b"],
        ) is None


class TestSingleCallVerdicts:
    def test_all_sites_uphold_refutes_with_complete_enumeration(
        self, tmp_path,
    ):
        res = _run_single_call(_bitmap_target(tmp_path, """
void a(struct bitmap *m) {
    bitmap_free(m);
    m = NULL;
}
void b(struct ctx *c) {
    bitmap_free(c->map);
}
"""))
        assert res.outcome == "refuted", res.to_dict()
        assert all(s.grade == "structural" for s in res.sites)
        assert res.enumeration == "tree-scan"
        assert res.enumeration_complete is True
        d = res.to_dict()
        assert d["enumeration_complete"] is True
        assert "enumeration_notes" in d

    def test_straight_line_double_call_confirms(self, tmp_path):
        res = _run_single_call(_bitmap_target(tmp_path, """
void a(struct bitmap *m) {
    bitmap_free(m);
    bitmap_free(m);
}
"""))
        assert res.outcome == "confirmed", res.to_dict()
        assert "double invocation" in res.reason

    def test_branch_separated_calls_stay_inconclusive(self, tmp_path):
        # if/else: exactly one call per execution — a re-pass across
        # a branch token must never confirm.
        res = _run_single_call(_bitmap_target(tmp_path, """
void a(struct bitmap *m, int x) {
    if (x)
        bitmap_free(m);
    else
        bitmap_free(m);
}
"""))
        assert res.outcome == "inconclusive", res.to_dict()

    def test_reuse_after_call_gates_to_inconclusive(self, tmp_path):
        res = _run_single_call(_bitmap_target(tmp_path, """
int a(struct bitmap *m) {
    bitmap_free(m);
    return m->len;
}
"""))
        assert res.outcome == "inconclusive", res.to_dict()

    def test_function_pointer_escape_blocks_completeness(self, tmp_path):
        # The callee's address is taken in a dispatch table: indirect
        # callers are possible, the textual enumeration cannot be
        # trusted complete, and demotion consumers must decline.
        res = _run_single_call(_bitmap_target(tmp_path, """
struct ops { void (*fr)(struct bitmap *); };
struct ops O = { .fr = bitmap_free };
void a(struct bitmap *m) {
    bitmap_free(m);
}
"""))
        assert res.outcome == "refuted"
        assert res.enumeration_complete is False
        assert any("address" in n for n in res.enumeration_notes)

    def test_test_file_double_call_does_not_confirm(self, tmp_path):
        # Idempotence tests double-call teardown helpers on purpose —
        # a literal double invocation in test code is not production
        # caller evidence and must not mint a confirmation.
        target = _bitmap_target(tmp_path, """
void session_close(struct bitmap *m) {
    bitmap_free(m);
    m = NULL;
}
""")
        tests_dir = target / "tests"
        tests_dir.mkdir()
        (tests_dir / "bitmap_test.c").write_text("""
void test_double_free_safe(struct bitmap *m) {
    bitmap_free(m);
    bitmap_free(m);
}
""")
        res = _run_single_call(target)
        assert res.outcome == "refuted", res.to_dict()
        assert all(s.file == "callers.c" for s in res.sites)
        assert any("test-file" in n for n in res.enumeration_notes)

    def test_hostile_column_zero_brace_cannot_fake_last_use(
        self, tmp_path,
    ):
        # Attacker-formatted column-0 braces inside the caller body
        # must not truncate the post-call region and mint a false
        # "last use" receipt (the reuse below the fake close would
        # then be invisible to the refutation).
        res = _run_single_call(_bitmap_target(tmp_path, """
void a(struct bitmap *m, int x) {
    if (x)
{
        bitmap_free(m);
}
    use(m);
}
"""))
        assert res.outcome == "inconclusive", res.to_dict()

    def test_window_bounded_last_use_is_lexical_and_cannot_refute(
        self, tmp_path,
    ):
        # No inferrable extent (no column-0 definition start above the
        # call): the no-reuse receipt is window-bounded, grades
        # lexical, and the aggregate stays inconclusive even though a
        # reuse hides just past the window.
        pad = "\n".join(f"    pad_{i}();" for i in range(16))
        res = _run_single_call(_bitmap_target(
            tmp_path,
            f"    bitmap_free(m);\n{pad}\n    reuse(m);\n",
        ))
        assert res.outcome == "inconclusive", res.to_dict()
        assert "lexical" in res.reason
        assert all(
            s.grade == "lexical"
            for s in res.sites if s.verdict == "guarded"
        )


class TestSingleCallConfirmPrecision:
    def test_free_two_fields_does_not_confirm(self, tmp_path):
        # The confirm lane must match the FULL argument expression:
        # freeing two different fields of the same struct is the
        # ubiquitous cleanup shape, not a double free.
        res = _run_single_call(_bitmap_target(tmp_path, """
void a(struct s *s) {
    bitmap_free(s->a);
    bitmap_free(s->b);
}
"""))
        assert res.outcome != "confirmed", res.to_dict()

    def test_intervening_call_does_not_confirm(self, tmp_path):
        # The function between the two calls may not return
        # (exit/abort/longjmp) — a re-pass across it is not a literal
        # double invocation.
        res = _run_single_call(_bitmap_target(tmp_path, """
void a(struct bitmap *m) {
    bitmap_free(m);
    fatal_exit(1);
    bitmap_free(m);
}
"""))
        assert res.outcome == "inconclusive", res.to_dict()

    def test_same_name_definition_elsewhere_declines(self, tmp_path):
        # A same-name static in another TU: textual call sites cannot
        # be attributed to the reviewed function — neither confirm nor
        # refute.
        target = _bitmap_target(tmp_path, """
void a(struct bitmap *m) {
    bitmap_free(m);
    m = NULL;
}
""")
        (target / "other.c").write_text(
            "static void bitmap_free(struct bitmap *b) { }\n"
            "void oc(struct bitmap *x) {\n"
            "    bitmap_free(x);\n"
            "    bitmap_free(x);\n"
            "}\n",
        )
        res = _run_single_call(target)
        assert res.outcome == "inconclusive", res.to_dict()
        assert "definition" in res.reason


class TestSingleCallRefutePrecision:
    def test_pre_call_field_alias_blocks_refutation(self, tmp_path):
        # h->m = m before the call keeps the resource reachable
        # through a name the post-call scan does not track — a real
        # double free (free(m) then free(h->m)) must not be refuted.
        res = _run_single_call(_bitmap_target(tmp_path, """
void a(struct holder *h, struct bitmap *m) {
    h->m = m;
    bitmap_free(m);
    bitmap_free(h->m);
}
"""))
        assert res.outcome == "inconclusive", res.to_dict()

    def test_loop_enclosing_call_blocks_refutation(self, tmp_path):
        res = _run_single_call(_bitmap_target(tmp_path, """
void a(struct bitmap *m) {
    int i;
    for (i = 0; i < 2; i++)
        bitmap_free(m);
}
"""))
        assert res.outcome == "inconclusive", res.to_dict()

    def test_goto_loop_blocks_refutation(self, tmp_path):
        res = _run_single_call(_bitmap_target(tmp_path, """
void a(struct bitmap *m) {
again:
    bitmap_free(m);
    if (retry())
        goto again;
}
"""))
        assert res.outcome == "inconclusive", res.to_dict()

    def test_non_local_argument_blocks_refutation(self, tmp_path):
        # The same global freed from two different callers is a
        # cross-caller sequential double free no per-site analysis can
        # order — refutation requires a visibly caller-local argument.
        res = _run_single_call(_bitmap_target(tmp_path, """
struct bitmap *g;
void a(void) {
    bitmap_free(g);
}
void b(void) {
    bitmap_free(g);
}
"""))
        assert res.outcome == "inconclusive", res.to_dict()
        assert any("local" in s.evidence for s in res.sites)

    def test_brace_anomaly_blocks_structural_receipts(self, tmp_path):
        # Unbalanced braces under preprocessor conditionals make
        # extent inference untrustworthy in BOTH directions — no
        # structural guard receipts may be issued for the file.
        res = _run_single_call(_bitmap_target(tmp_path, """
void a(struct bitmap *m, int x) {
#ifdef NEVER
}
#endif
    if (x)
{
        bitmap_free(m);
}
    bitmap_free(m);
}
"""))
        assert res.outcome != "refuted", res.to_dict()
        assert all(
            s.grade == "lexical"
            for s in res.sites if s.verdict == "guarded"
        )


class TestEnumerationCompletenessHonesty:
    def test_oversized_file_skip_blocks_completeness(self, tmp_path):
        target = _bitmap_target(tmp_path, """
void a(struct bitmap *m) {
    bitmap_free(m);
    m = NULL;
}
""")
        (target / "huge.c").write_text(
            "void h(struct bitmap *q) {\n"
            "    bitmap_free(q);\n"
            "    bitmap_free(q);\n"
            "}\n" + "x" * 2_100_000,
        )
        res = _run_single_call(target)
        assert res.enumeration_complete is False
        assert any("byte cap" in n for n in res.enumeration_notes)

    def test_alias_attribute_blocks_completeness(self, tmp_path):
        # alias("name") puts the target inside a string literal the
        # sanitized view blanks — the raw-text check must catch it.
        target = _bitmap_target(tmp_path, """
void a(struct bitmap *m) {
    bitmap_free(m);
    m = NULL;
}
""")
        (target / "alias.c").write_text(
            "extern void bf2(struct bitmap *) "
            '__attribute__((alias("bitmap_free")));\n',
        )
        res = _run_single_call(target)
        assert res.enumeration_complete is False
        assert any("alias" in n for n in res.enumeration_notes)

    def test_site_budget_cap_blocks_completeness(self, tmp_path):
        # Pathological site counts are capped BEFORE paying per-site
        # region analysis — bounded work, and a capped enumeration is
        # never complete.
        from core.audit.api_boundary import _MAX_SITES_ENUMERATED

        target = _bitmap_target(
            tmp_path,
            "void z(struct bitmap *q) {"
            + "bitmap_free(q);" * 2000
            + "}",
        )
        res = _run_single_call(target)
        assert len(res.sites) <= _MAX_SITES_ENUMERATED
        assert res.enumeration_complete is False
        assert any("budget" in n for n in res.enumeration_notes)


class TestWrongTargetDefence:
    def test_hypothesis_naming_other_callee_declines(self, tmp_path):
        target = _bitmap_target(tmp_path, """
void a(struct bitmap *m) {
    bitmap_free(m);
    m = NULL;
}
""")
        res = run_api_boundary_check(
            target, "bitmap.c", "bitmap_free",
            "double free if a caller invokes other_teardown twice "
            "on the same pointer",
            def_span=(1, 7),
        )
        assert res.outcome == "inconclusive"
        assert "other_teardown" in res.reason

    def test_pronoun_target_is_not_a_name(self):
        from core.audit.api_boundary import _named_invoke_target

        assert _named_invoke_target(
            "crashes if a caller invokes it twice",
        ) == ""
        assert _named_invoke_target(
            "double free if a caller invokes bitmap_free twice",
        ) == "bitmap_free"


class TestDispatchWiring:
    def test_chain_builder_emits_api_boundary_step(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(
            "NULL host is only reachable from external API consumers "
            "of this exported function",
            "crypto/bio/bio_addr.c",
        )
        assert any(e["type"] == "api_boundary" for e in chain), (
            "caller-contract hypotheses must dispatch the boundary "
            "channel"
        )

    def test_non_contract_hypotheses_do_not_dispatch(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(
            "unchecked memcpy overflows the destination buffer",
            "a.c",
        )
        assert not any(e["type"] == "api_boundary" for e in chain)

    def test_single_call_hypothesis_dispatches_channel(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(HYP_SINGLE_CALL, "bitmap.c")
        assert any(e["type"] == "api_boundary" for e in chain)

    def test_cwe_route_gated_on_caller_conditional_phrasing(self):
        from core.audit.orchestrator import _cwe_fallback_chain

        conditional = _cwe_fallback_chain("CWE-416", HYP_SINGLE_CALL)
        assert any(e["type"] == "api_boundary" for e in conditional)
        in_body = _cwe_fallback_chain(
            "CWE-416", "use after free of buf in the parse loop",
        )
        assert not any(e["type"] == "api_boundary" for e in in_body)

    def test_tool_chain_runs_channel(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            TierCounters,
            _run_tool_chain,
        )

        _write_target(tmp_path, """
int careless(void) {
    return bio_lookup_ex(NULL, 80, 2);
}
""")
        counters = {"api_boundary": TierCounters()}
        confirmed = _run_tool_chain(
            [{"type": "api_boundary", "config": {}}],
            config=OrchestratorConfig(target_path=tmp_path, out_dir=None),
            file_path="lookup.c",
            function_name="bio_lookup_ex",
            source=DEFINITION,
            hypothesis=HYP_NULL,
            tier_counters=counters,
        )
        assert confirmed == ["api_boundary:caller-contract"]
        assert counters["api_boundary"].confirmed == 1


class TestDeclaredLocallyDerefStore:
    """A deref-store (`*g = x;` — assignment THROUGH g) is not a
    declaration OF g: the old bare-star alternative read it as a
    local declaration, so a single-call contract over a global
    pointer whose pointee is stored pre-call could be graded guarded
    and feed a refuted aggregate."""

    @staticmethod
    def _risk(before: str):
        from core.audit.api_boundary import _single_call_precall_risk
        return _single_call_precall_risk(
            {"before_body": before, "after_window": ""}, "g",
        )

    def test_deref_store_is_not_a_local_declaration(self):
        risk = self._risk("int f(int x) { *g = x; f2(g); ")
        assert risk is not None
        assert "not provably local" in risk

    def test_pointer_parameter_still_counts(self):
        assert self._risk("int f(char *g) { ") is None

    def test_local_pointer_declaration_still_counts(self):
        assert self._risk("int f(void) { struct buf *g; ") is None

    def test_multi_declarator_star_still_counts(self):
        assert self._risk("int f(void) { int a, *g; ") is None
