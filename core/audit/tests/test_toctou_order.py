"""Control-flow ordering refinement of lexical TOCTOU candidates.

The refiner (core.audit.toctou_order) may only ever NARROW the lexical
verdict: prune provably unordered pairs, discharge atomic use idioms to
inconclusive, and stamp verified orderings. Anything unmodeled must
sustain the lexical baseline exactly. Every prune/discharge case here
carries a no-file-path discriminator showing the lexical lane would
have fired — proof the narrowing is the refiner's work.
"""

import textwrap

import pytest

from core.audit.condition_smt import check_toctou
from core.audit.toctou_order import OrderVerdict, ToctouRefiner

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_c")


def _c(body: str) -> str:
    return textwrap.dedent(body).strip() + "\n"


CLASSIC = _c("""
    void F(const char *p) {
        if (access(p, R_OK) != 0) return;
        open(p, O_RDONLY);
    }
""")


# ---------------------------------------------------------------------------
# Sustained findings: verified ordering annotated, baseline untouched
# ---------------------------------------------------------------------------


def test_classic_race_sustained_and_verified_on_the_cfg():
    result = check_toctou(CLASSIC, file_path="unit.c")
    assert result.toctou_found is True
    assert result.check_call == "access"
    assert result.use_call == "open"
    assert result.ordering_verified is True
    assert "verified" in result.reasoning
    assert result.to_dict()["ordering_verified"] is True


def test_lexical_baseline_without_file_path_is_unchanged():
    result = check_toctou(CLASSIC)
    assert result.toctou_found is True
    assert result.ordering_verified is False
    assert "ordering_verified" not in result.to_dict()


def test_non_c_file_path_keeps_the_lexical_lane():
    source = "import os\ndef f(p):\n    if os.path.exists(p):\n        open(p)\n"
    result = check_toctou(source, file_path="script.py")
    assert result.toctou_found is True
    assert result.ordering_verified is False


def test_unmodeled_preprocessor_sustains_the_lexical_baseline():
    source = _c("""
        void F(const char *p) {
            if (access(p, R_OK) != 0) return;
        #ifdef EXTRA
            g();
        #endif
            open(p, O_RDONLY);
        }
    """)
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.ordering_verified is False


def test_reassignment_on_only_one_path_sustains():
    source = _c("""
        void F(char *p, char *q, int c) {
            if (access(p, R_OK) != 0) return;
            if (c) { p = q; }
            open(p, O_RDONLY);
        }
    """)
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.ordering_verified is True


def test_composed_path_expression_still_pairs_and_verifies():
    source = _c("""
        void F(char *dir, char *name) {
            if (access(dir, R_OK) != 0) return;
            open(strcat(dir, name), O_RDONLY);
        }
    """)
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.variable == "dir"
    assert result.ordering_verified is True


# ---------------------------------------------------------------------------
# Prunes: provably unordered pairs are removed, with the lexical
# discriminator showing each would have fired before
# ---------------------------------------------------------------------------

CROSS_FUNCTION = _c("""
    void check_it(const char *p) {
        if (access(p, R_OK) != 0) return;
    }
    void use_it(const char *p) {
        open(p, O_RDONLY);
    }
""")


def test_cross_function_pair_is_pruned():
    assert check_toctou(CROSS_FUNCTION).toctou_found is True
    result = check_toctou(CROSS_FUNCTION, file_path="unit.c")
    assert result.toctou_found is False
    assert result.applicable is True
    assert "pruned" in result.reasoning


MUTUALLY_EXCLUSIVE = _c("""
    void F(const char *p, int mode) {
        if (mode) {
            if (access(p, R_OK) != 0) return;
        } else {
            open(p, O_RDONLY);
        }
    }
""")


def test_mutually_exclusive_branches_are_pruned():
    assert check_toctou(MUTUALLY_EXCLUSIVE).toctou_found is True
    result = check_toctou(MUTUALLY_EXCLUSIVE, file_path="unit.c")
    assert result.toctou_found is False
    assert "pruned" in result.reasoning


REASSIGNED = _c("""
    void F(char *p, char *q) {
        if (access(p, R_OK) != 0) return;
        p = q;
        open(p, O_RDONLY);
    }
""")


def test_variable_reassigned_on_every_path_is_pruned():
    assert check_toctou(REASSIGNED).toctou_found is True
    result = check_toctou(REASSIGNED, file_path="unit.c")
    assert result.toctou_found is False
    assert "pruned" in result.reasoning


def test_self_referencing_reassignment_sustains():
    # p = realpath(p, 0) derives the used value from the checked one:
    # the race through the derived path is real, so no prune.
    source = _c("""
        void F(char *p) {
            if (access(p, R_OK) != 0) return;
            p = realpath(p, 0);
            open(p, O_RDONLY);
        }
    """)
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.ordering_verified is True


def test_plain_self_assignment_sustains():
    source = REASSIGNED.replace("p = q;", "p = p;")
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.ordering_verified is True


def test_compound_assignment_is_not_a_kill():
    source = REASSIGNED.replace("p = q;", "p += 1;")
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.ordering_verified is True


def test_inner_scope_shadow_declaration_sustains():
    # The block-scoped p is a NEW object; the outer checked p flows to
    # the use untouched. A prune here would clear a real race.
    source = _c("""
        int F(const char *p) {
            if (access(p, R_OK) != 0) return -1;
            { char *p = tmpname(); log_name(p); }
            return open(p, O_RDONLY);
        }
    """)
    assert check_toctou(source).toctou_found is True
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.ordering_verified is True


def test_shadowed_name_stands_down_the_kill_prune():
    # An assignment to a shadowed name targets the inner object; with
    # two declarations of the name in scope the kill-prune must not run.
    source = _c("""
        int F(const char *p) {
            if (access(p, R_OK) != 0) return -1;
            { char *p; p = tmpname(); log_name(p); }
            return open(p, O_RDONLY);
        }
    """)
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.ordering_verified is True


# ---------------------------------------------------------------------------
# Discharges: atomic use idioms compose to inconclusive, never refuted
# ---------------------------------------------------------------------------

NOFOLLOW = _c("""
    void F(const char *p) {
        if (access(p, R_OK) != 0) return;
        open(p, O_RDONLY | O_NOFOLLOW);
    }
""")


def test_o_nofollow_discharges_to_inconclusive():
    assert check_toctou(NOFOLLOW).toctou_found is True
    result = check_toctou(NOFOLLOW, file_path="unit.c")
    assert result.toctou_found is False
    assert result.applicable is False
    assert "mitigated" in result.reasoning
    assert result.to_dict()["applicable"] is False


def test_o_creat_o_excl_discharges():
    source = _c("""
        void F(const char *p) {
            if (access(p, F_OK) == 0) return;
            open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
        }
    """)
    assert check_toctou(source).toctou_found is True
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is False
    assert result.applicable is False


def test_masked_out_nofollow_is_not_discharged():
    # ``flags & ~O_NOFOLLOW`` textually contains the flag name while
    # stripping the flag itself; only a plain |-composition may match.
    source = _c("""
        void F(const char *p, int flags) {
            if (access(p, R_OK) != 0) return;
            open(p, flags & ~O_NOFOLLOW);
        }
    """)
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.ordering_verified is True


def test_commented_flag_name_is_not_discharged():
    # Structural descent never treats comment text as an active flag,
    # even when the comment sits inside the flags expression itself —
    # a raw-text match on the argument would see "O_NOFOLLOW" here.
    source = _c("""
        void F(const char *p) {
            if (access(p, R_OK) != 0) return;
            open(p, (O_RDONLY /* | O_NOFOLLOW */));
        }
    """)
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.ordering_verified is True


def test_o_creat_alone_is_not_discharged():
    source = _c("""
        void F(const char *p) {
            if (access(p, F_OK) == 0) return;
            open(p, O_WRONLY | O_CREAT, 0600);
        }
    """)
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.ordering_verified is True


def test_fopen_exclusive_mode_discharges_but_plain_mode_sustains():
    exclusive = _c("""
        void F(const char *p) {
            if (access(p, F_OK) == 0) return;
            fopen(p, "wx");
        }
    """)
    assert check_toctou(exclusive).toctou_found is True
    result = check_toctou(exclusive, file_path="unit.c")
    assert result.toctou_found is False
    assert result.applicable is False

    plain = exclusive.replace('"wx"', '"w"')
    result = check_toctou(plain, file_path="unit.c")
    assert result.toctou_found is True
    assert result.ordering_verified is True


def test_discharge_never_outranks_a_prune():
    # The atomic flag sits in a different function from the check: the
    # pair is not an ordered flow at all, so "mitigated" would be the
    # wrong story — the prune must win.
    source = _c("""
        void check_it(const char *p) {
            if (access(p, R_OK) != 0) return;
        }
        void use_it(const char *p) {
            open(p, O_RDONLY | O_NOFOLLOW);
        }
    """)
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is False
    assert result.applicable is True
    assert "pruned" in result.reasoning


# ---------------------------------------------------------------------------
# Argument-relatedness tightening (lexical lane, all languages)
# ---------------------------------------------------------------------------


def test_prefix_variable_names_no_longer_pair():
    source = _c("""
        void F(const char *p, const char *path) {
            if (access(p, R_OK) != 0) return;
            open(path, O_RDONLY);
        }
    """)
    # 'p' is a substring of 'path' but not an identifier-boundary
    # occurrence — different variables, no candidate even lexically.
    result = check_toctou(source)
    assert result.toctou_found is False
    assert result.reasoning == "no TOCTOU pattern found"


# ---------------------------------------------------------------------------
# Double fetch
# ---------------------------------------------------------------------------


def test_double_fetch_in_one_function_is_verified():
    source = _c("""
        int F(void *dst, const void *uptr) {
            copy_from_user(dst, uptr, 8);
            copy_from_user(dst, uptr, 16);
            return 0;
        }
    """)
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is True
    assert result.variable == "uptr"
    assert result.ordering_verified is True


def test_double_fetch_across_functions_is_pruned():
    source = _c("""
        int first(void *dst, const void *uptr) {
            return copy_from_user(dst, uptr, 8);
        }
        int second(void *dst, const void *uptr) {
            return copy_from_user(dst, uptr, 16);
        }
    """)
    assert check_toctou(source).toctou_found is True
    result = check_toctou(source, file_path="unit.c")
    assert result.toctou_found is False
    assert "pruned" in result.reasoning


# ---------------------------------------------------------------------------
# Refiner robustness: anything unmodeled sustains, never concludes
# ---------------------------------------------------------------------------


def test_unparseable_source_yields_unmodeled_sustains():
    refiner = ToctouRefiner("void F( {{{")
    verdict = refiner.refine("access", 1, "open", 2, "p")
    assert verdict.status == "sustained"
    assert verdict.verified is False


def test_oversized_source_yields_unmodeled_sustains():
    refiner = ToctouRefiner("x" * ((1 << 20) + 1))
    verdict = refiner.refine("access", 1, "open", 2, "p")
    assert verdict.status == "sustained"
    assert verdict.verified is False


def test_unlocatable_call_sustains():
    refiner = ToctouRefiner(CLASSIC)
    verdict = refiner.refine("access", 99, "open", 100, "p")
    assert verdict.status == "sustained"
    assert verdict.verified is False


def test_ambiguous_duplicate_call_on_one_line_sustains():
    source = _c("""
        void F(const char *p, const char *q) {
            if (access(p, R_OK) != 0 || access(q, R_OK) != 0) return;
            open(p, O_RDONLY);
        }
    """)
    refiner = ToctouRefiner(source)
    verdict = refiner.refine("access", 2, "open", 3, "p")
    assert verdict.status == "sustained"
    assert verdict.verified is False


def test_verdict_statuses_are_closed():
    assert OrderVerdict(status="sustained").verified is False
    refiner = ToctouRefiner(CLASSIC)
    verdict = refiner.refine("access", 2, "open", 3, "p")
    assert verdict.status == "sustained"
    assert verdict.verified is True


# ---------------------------------------------------------------------------
# Sweep integration: confirmed carries the stamp, discharge maps to
# inconclusive, prunes never exceed inconclusive at the boundary
# ---------------------------------------------------------------------------


def _sweep(source: str, function_name: str = "F"):
    from core.audit.sweep import _run_smt_verb_inner
    return _run_smt_verb_inner(
        file_path="unit.c",
        function_name=function_name,
        verb="check-toctou",
        source=source,
        hypothesis="TOCTOU race between check and use",
    )


def test_sweep_confirmed_finding_carries_the_ordering_stamp():
    result = _sweep(CLASSIC)
    assert result.outcome == "confirmed"
    assert result.details["ordering_verified"] is True
    assert result.details["oracle_scope"] == "source-pattern"


def test_sweep_discharge_is_inconclusive_not_refuted():
    result = _sweep(NOFOLLOW)
    assert result.outcome == "inconclusive"
    assert result.details["applicable"] is False


def test_sweep_prune_is_capped_at_inconclusive():
    result = _sweep(MUTUALLY_EXCLUSIVE)
    assert result.outcome == "inconclusive"
    assert "pruned" in result.details["reasoning"]
