"""Tests for the TranslationView seam (U2).

At this stage the provider is identity for every language — the seam is
introduced without behavior change. Later units specialize the C/C++ branch
(#if 0 blanking, macro flags) and add a non-identity line_map (real cpp).
"""

from __future__ import annotations

from core.inventory.translation_view import (
    IDENTITY_LINE_MAP,
    LineMap,
    TranslationView,
    detect_macro_call_targets,
    detect_preprocessor_dead_ranges,
    preprocess_view,
)


def _names(view, lang="c"):
    from core.inventory.extractors import extract_items
    return {i.name for i in extract_items("t." + lang, lang, view.parse_text)}


def test_identity_view_returns_content_unchanged():
    src = "def f():\n    return 1\n"
    v = preprocess_view("t.py", "python", src)
    assert v.parse_text == src
    assert v.fidelity == 0
    assert v.masking_flags == frozenset()
    assert v.line_map is IDENTITY_LINE_MAP


def test_clean_c_file_text_unchanged_but_fidelity_1():
    # A C file with no dead preprocessor arms: blanking is a no-op so
    # parse_text == content, but it went through the C-family provider so
    # fidelity is 1 (not 0).
    src = "void a(void){ b(); }\nvoid b(void){}\n"
    v = preprocess_view("t.c", "c", src)
    assert v.parse_text == src
    assert v.fidelity == 1


def test_identity_line_map_is_identity():
    lm = IDENTITY_LINE_MAP
    for n in (1, 5, 42, 1000):
        assert lm.to_source(n) == n


def test_line_map_with_breakpoints_maps_offsets():
    # Layer-3 shape: parse line 10 maps to source line 3, and lines after a
    # breakpoint advance in lockstep until the next breakpoint.
    lm = LineMap(entries=((1, 1), (10, 3)))
    assert lm.to_source(1) == 1
    assert lm.to_source(2) == 2        # within first segment
    assert lm.to_source(10) == 3       # breakpoint
    assert lm.to_source(12) == 5       # 3 + (12-10)


def test_view_is_frozen():
    v = TranslationView(parse_text="x")
    try:
        v.parse_text = "y"            # type: ignore[misc]
        assert False, "TranslationView must be immutable"
    except Exception:
        pass


def test_empty_content():
    v = preprocess_view("t.py", "python", "")
    assert v.parse_text == ""
    assert v.fidelity == 0


# ---------------------------------------------------------------------------
# U3 — C/C++ #if 0 blanking
# ---------------------------------------------------------------------------

_IF0 = (
    "#if 0\n"
    "void dead_fn(void) { system(cmd); }\n"
    "#endif\n"
    "void live_fn(void) { return; }\n"
)


def test_c_if0_function_blanked_by_default():
    v = preprocess_view("t.c", "c", _IF0)
    assert v.fidelity == 1
    assert _names(v) == {"live_fn"}, "#if 0 function must not survive default view"


def test_c_if0_function_present_under_allow_unreachable():
    v = preprocess_view("t.c", "c", _IF0, allow_unreachable=True)
    assert v.fidelity == 0
    assert _names(v) == {"dead_fn", "live_fn"}, (
        "isolation mode must keep disabled code for review"
    )


def test_blanking_preserves_line_count():
    v = preprocess_view("t.c", "c", _IF0)
    assert v.parse_text.count("\n") == _IF0.count("\n")  # identity line map holds


def test_ifdef_not_blanked_conservative():
    # #ifdef X is config-dependent — must NOT be treated as dead (would be a
    # false negative: the function is live in builds that define X).
    src = (
        "#ifdef HAVE_FOO\n"
        "void maybe_live(void) { do_thing(); }\n"
        "#endif\n"
    )
    assert detect_preprocessor_dead_ranges(src) == []
    v = preprocess_view("t.c", "c", src)
    assert _names(v) == {"maybe_live"}


def test_if0_else_arm_is_live():
    src = (
        "#if 0\n"
        "void dead_one(void) {}\n"
        "#else\n"
        "void live_one(void) {}\n"
        "#endif\n"
    )
    v = preprocess_view("t.c", "c", src)
    assert _names(v) == {"live_one"}


def test_cpp_also_blanked():
    # Assert on the view's contract (parse_text blanking), not on extracted
    # names — qualified C++ method extraction needs tree-sitter-cpp, which
    # CI's stdlib-fallback path lacks (same divergence as the #620 fix).
    src = "#if 0\nvoid Dead::m() {}\n#endif\nvoid Live::m() {}\n"
    v = preprocess_view("t.cpp", "cpp", src)
    assert v.fidelity == 1
    assert "Dead::m" not in v.parse_text            # dead arm blanked
    assert "void Live::m() {}" in v.parse_text       # live arm intact


def test_detect_ranges_only_fire_on_literal_zero():
    # Conservatism contract: ifdef/symbol/expr never produce ranges.
    for cond in ("#ifdef X", "#if defined(X)", "#if VERSION > 3", "#if A && B"):
        src = cond + "\nvoid f(void){}\n#endif\n"
        assert detect_preprocessor_dead_ranges(src) == [], cond


# ---------------------------------------------------------------------------
# U4 — function-like-macro call targets
# ---------------------------------------------------------------------------


def test_macro_body_call_target_detected():
    src = "#define CALL_F(x) f(x)\nstatic int f(int x){ return x; }\n"
    assert "f" in detect_macro_call_targets(src)


def test_macro_with_line_continuation():
    src = "#define WRAP(a) \\\n    do_thing(a)\nvoid u(void){}\n"
    assert "do_thing" in detect_macro_call_targets(src)


def test_object_like_macro_not_a_target():
    # Object-like macro (no parens) — not a function-like macro; no targets.
    src = "#define MAX 100\nint f(void){ return MAX; }\n"
    assert detect_macro_call_targets(src) == set()


def test_control_keywords_excluded():
    src = "#define GUARD(x) if (x) return\n"
    got = detect_macro_call_targets(src)
    assert "if" not in got and "return" not in got


def test_macro_not_counted_as_calling_itself():
    src = "#define F(x) F(x)\n"          # pathological self-reference
    assert "F" not in detect_macro_call_targets(src)


def test_no_macros_empty():
    assert detect_macro_call_targets("int f(void){ return g(); }\n") == set()


def test_call_shaped_text_in_string_literal_not_a_target():
    # Adversarial FP: a format string with call-shaped text must not count.
    got = detect_macro_call_targets('#define LOG(x) fprintf(stderr, "evil(): %d", x)')
    assert got == {"fprintf"}, got


def test_call_shaped_text_in_comment_not_a_target():
    got = detect_macro_call_targets("#define X() /* go to handler() */ real_fn()")
    assert got == {"real_fn"}, got


def test_char_literal_paren_not_a_target():
    got = detect_macro_call_targets("#define C(x) g(x, ')')")
    assert got == {"g"}, got


# ---------------------------------------------------------------------------
# U12 — config-aware #ifdef / #if resolution (fidelity 2)
# ---------------------------------------------------------------------------

def _mc(defined=None, undefined=()):
    from core.build.macro_config import MacroConfig
    return MacroConfig(defined=dict(defined or {}),
                       undefined=frozenset(undefined))


def test_ifdef_known_undefined_is_dead():
    src = "#ifdef HAVE_FOO\nvoid gone(void){}\n#endif\n"
    mc = _mc(undefined={"HAVE_FOO"})
    assert detect_preprocessor_dead_ranges(src, mc) == [(2, 2)]


def test_ifdef_known_defined_is_live():
    src = "#ifdef HAVE_FOO\nvoid kept(void){}\n#endif\n"
    mc = _mc(defined={"HAVE_FOO": "1"})
    assert detect_preprocessor_dead_ranges(src, mc) == []


def test_ifdef_absent_symbol_stays_unknown_even_with_config():
    # The load-bearing soundness property: a symbol NOT in the config might
    # still be #define'd in a header — never treat absence as undefined.
    src = "#ifdef MAYBE_IN_HEADER\nvoid x(void){}\n#endif\n"
    mc = _mc(defined={"SOMETHING_ELSE": "1"}, undefined={"AND_ANOTHER"})
    assert detect_preprocessor_dead_ranges(src, mc) == []


def test_ifndef_known_defined_is_dead():
    src = "#ifndef HAVE_FOO\nvoid fallback(void){}\n#endif\n"
    mc = _mc(defined={"HAVE_FOO": "1"})
    assert detect_preprocessor_dead_ranges(src, mc) == [(2, 2)]


def test_ifndef_known_undefined_is_live():
    src = "#ifndef HAVE_FOO\nvoid fallback(void){}\n#endif\n"
    mc = _mc(undefined={"HAVE_FOO"})
    assert detect_preprocessor_dead_ranges(src, mc) == []


def test_if_defined_and_negation():
    on = "#if defined(X)\nvoid a(void){}\n#endif\n"
    off = "#if !defined(X)\nvoid b(void){}\n#endif\n"
    mc = _mc(defined={"X": "1"})
    assert detect_preprocessor_dead_ranges(on, mc) == []
    assert detect_preprocessor_dead_ranges(off, mc) == [(2, 2)]


def test_if_macro_value_zero_is_dead_but_ifdef_still_live():
    # -DFLAG=0 : the macro IS defined (so #ifdef is live) but its value is 0
    # (so #if is dead). The two forms must not be conflated.
    mc = _mc(defined={"FLAG": "0"})
    ifdef_src = "#ifdef FLAG\nvoid a(void){}\n#endif\n"
    if_src = "#if FLAG\nvoid b(void){}\n#endif\n"
    assert detect_preprocessor_dead_ranges(ifdef_src, mc) == []
    assert detect_preprocessor_dead_ranges(if_src, mc) == [(2, 2)]


def test_if_macro_value_nonzero_is_live():
    mc = _mc(defined={"LEVEL": "2"})
    src = "#if LEVEL\nvoid a(void){}\n#endif\n"
    assert detect_preprocessor_dead_ranges(src, mc) == []


def test_if_known_undefined_identifier_evaluates_to_zero():
    # In #if, an undefined identifier is 0 → arm dead. Only when KNOWN-undef.
    mc = _mc(undefined={"NOPE"})
    src = "#if NOPE\nvoid a(void){}\n#endif\n"
    assert detect_preprocessor_dead_ranges(src, mc) == [(2, 2)]


def test_compound_expression_stays_unknown_with_config():
    # We do not partially evaluate &&/|| — stays untouched (safe).
    mc = _mc(defined={"A": "1"}, undefined={"B"})
    for cond in ("#if defined(A) && defined(B)",
                 "#if A || B",
                 "#if VERSION > 3"):
        src = cond + "\nvoid f(void){}\n#endif\n"
        assert detect_preprocessor_dead_ranges(src, mc) == [], cond


def test_nested_dead_arm_with_config():
    src = (
        "#ifdef OFF\n"
        "void outer(void){}\n"
        "#ifdef ALSO\n"
        "void inner(void){}\n"
        "#endif\n"
        "#endif\n"
    )
    mc = _mc(undefined={"OFF"}, defined={"ALSO": "1"})
    # Whole outer arm dead (OFF undefined) — inner body dead regardless of
    # ALSO; the inner #ifdef/#endif directive lines are left in place.
    assert detect_preprocessor_dead_ranges(src, mc) == [(2, 2), (4, 4)]


def test_elif_resolved_against_config():
    src = (
        "#if defined(A)\n"
        "void a(void){}\n"
        "#elif defined(B)\n"
        "void b(void){}\n"
        "#else\n"
        "void c(void){}\n"
        "#endif\n"
    )
    # A undefined, B defined → a dead, b live, c dead (only body lines).
    mc = _mc(defined={"B": "1"}, undefined={"A"})
    assert detect_preprocessor_dead_ranges(src, mc) == [(2, 2), (6, 6)]


def test_preprocess_view_fidelity_2_with_config():
    src = "#ifdef OFF\nvoid gone(void){}\n#endif\nvoid kept(void){}\n"
    mc = _mc(undefined={"OFF"})
    v = preprocess_view("t.c", "c", src, config=mc)
    assert v.fidelity == 2
    assert _names(v) == {"kept"}
    assert v.line_map is IDENTITY_LINE_MAP        # blanking preserves lines


def test_preprocess_view_empty_config_is_fidelity_1():
    from core.build.macro_config import MacroConfig
    src = "#if 0\nvoid d(void){}\n#endif\nvoid k(void){}\n"
    v = preprocess_view("t.c", "c", src, config=MacroConfig())
    assert v.fidelity == 1                          # empty config → literal-only
    assert _names(v) == {"k"}


def test_config_aware_blanking_still_blanks_literal_zero():
    mc = _mc(defined={"X": "1"})
    src = "#if 0\nvoid d(void){}\n#endif\nvoid k(void){}\n"
    assert detect_preprocessor_dead_ranges(src, mc) == [(2, 2)]


def test_allow_unreachable_ignores_config():
    # Isolation mode returns the raw view even when a config is supplied.
    src = "#ifdef OFF\nvoid gone(void){}\n#endif\n"
    mc = _mc(undefined={"OFF"})
    v = preprocess_view("t.c", "c", src, allow_unreachable=True, config=mc)
    assert v.fidelity == 0
    assert "gone" in v.parse_text


# --- over-fire (false-negative) guards: unknown leading arms in chains ------

def test_elif_unknown_leading_arm_does_not_blank_live_arms():
    # #if defined(A) with A UNKNOWN (may be #define'd in a header). Even though
    # B is known-defined, neither arm1 (live when A defined) nor arm2 (live when
    # A undefined) may be blanked — only the #else, dead under every build
    # consistent with the config.
    src = (
        "#if defined(A)\n" "void a(void){}\n"
        "#elif defined(B)\n" "void b(void){}\n"
        "#else\n" "void c(void){}\n" "#endif\n"
    )
    mc = _mc(defined={"B": "1"})            # A unknown, B defined
    dead = detect_preprocessor_dead_ranges(src, mc)
    flat = {ln for lo, hi in dead for ln in range(lo, hi + 1)}
    assert 2 not in flat and 4 not in flat, "must not blank a possibly-live arm"


def test_elif_unknown_arm_after_known_false_blanks_nothing_more():
    # A known-undef → arm1 dead. B UNKNOWN → arm2 / arm3 could each be live, so
    # only arm1 may be blanked.
    src = (
        "#if defined(A)\n" "void a(void){}\n"
        "#elif defined(B)\n" "void b(void){}\n"
        "#else\n" "void c(void){}\n" "#endif\n"
    )
    mc = _mc(undefined={"A"})               # A undef, B unknown
    assert detect_preprocessor_dead_ranges(src, mc) == [(2, 2)]


def test_unknown_parent_does_not_blank_its_body():
    # OUTER unknown → its body survives; INNER explicitly-undef child is dead.
    src = (
        "#ifdef OUTER\n" "void o(void){}\n"
        "#ifdef INNER\n" "void i(void){}\n"
        "#endif\n" "#endif\n"
    )
    mc = _mc(undefined={"INNER"})           # OUTER unknown, INNER undef
    flat = {ln for lo, hi in detect_preprocessor_dead_ranges(src, mc)
            for ln in range(lo, hi + 1)}
    assert 2 not in flat, "must not blank body under an unknown #ifdef"
    assert 4 in flat, "explicitly-undef INNER arm should be dead"
