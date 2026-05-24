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
