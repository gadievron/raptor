"""Tests for :mod:`core.inventory.js_lexer`.

Focus: template-literal / interpolation parity on hostile shapes. The
lexer feeds enforce-eligible hard-suppress witnesses (dead-scope ranges,
module-load aborts), so a parity flip — template DATA lexed as code, or
real code blanked as template text — is a false-suppression lever for a
hostile repo. Every fixture here is valid ECMAScript (node-verified
shapes); the assertions pin that live code stays visible and string
data stays blanked.
"""

from __future__ import annotations

import pytest

from core.inventory.dead_scope import detect_dead_scopes
from core.inventory.js_lexer import JsLexAmbiguityError, blank_js_noncode
from core.inventory.module_load_abort import detect_module_load_abort


# ---------------------------------------------------------------------------
# Basic blanking sanity
# ---------------------------------------------------------------------------


def test_strings_comments_regexes_blanked_code_kept():
    src = (
        "// comment {\n"
        "const s = 'br}ace';\n"
        "const r = /}/g;\n"
        "function f() { return 1; }\n"
    )
    blanked = blank_js_noncode(src)
    assert "comment" not in blanked
    assert "br}ace" not in blanked
    assert "/}/" not in blanked
    assert "function f() { return 1; }" in blanked


def test_simple_template_blanked_wholesale():
    src = "exec(`echo ${input} }` );\nlet x = 1;\n"
    blanked = blank_js_noncode(src)
    assert "echo" not in blanked
    assert "let x = 1;" in blanked


# ---------------------------------------------------------------------------
# Interpolation holds a full expression (ES6 allows arbitrary nesting).
# A `}` inside a nested literal must NOT close the interpolation.
# ---------------------------------------------------------------------------


def test_nested_template_inside_interpolation_keeps_parity():
    # `${`}`}` is valid ES6 and evaluates to "}". Counting raw braces
    # closes the interpolation at the nested `}` and desyncs the
    # template-vs-code parity for the rest of the file.
    src = "const a = `${`}`}`;\nfunction live() { return 1; }\n"
    blanked = blank_js_noncode(src)
    assert "function live() { return 1; }" in blanked


def test_closing_brace_in_string_inside_interpolation():
    src = 'const x = `${"}"}tail`;\nfunction live() { return 1; }\n'
    blanked = blank_js_noncode(src)
    assert "tail" not in blanked
    assert "function live() { return 1; }" in blanked


def test_comment_and_regex_inside_interpolation():
    src = 'const y = `${ /*}*/ v.replace(/}/g, "x") }data`;\nlet ok = 1;\n'
    blanked = blank_js_noncode(src)
    assert "data" not in blanked
    assert "let ok = 1;" in blanked


def test_object_literal_inside_interpolation():
    # Code braces inside the interpolation must be depth-counted so the
    # REAL closer is recognised (not the object literal's).
    src = "const z = `${ fmt({a: {b: 1}}) }tail`;\nlet ok = 1;\n"
    blanked = blank_js_noncode(src)
    assert "fmt" in blanked  # interpolation code IS code
    assert "tail" not in blanked  # template text after the closer is not
    assert "let ok = 1;" in blanked


def test_unterminated_template_consumes_to_eof():
    src = "const t = `unterminated ${\nstill template-ish\n"
    # Must terminate and keep newlines (line arithmetic stays valid).
    blanked = blank_js_noncode(src)
    assert blanked.count("\n") == src.count("\n")


# ---------------------------------------------------------------------------
# Consumer-level: the hostile parity-flip shapes (node-verified — the
# files load fine and the functions execute).
# ---------------------------------------------------------------------------


def test_no_fabricated_module_load_abort_from_template_data():
    # `a` is the string "}"; `b` holds STRING DATA that merely looks
    # like a top-level throw. The module loads fine under node.
    src = (
        "const a = `${`}`}`;\n"
        "const b = `\n"
        "; throw new Boom();\n"
        "`;\n"
        "function live(req) { return req.q; }\n"
    )
    assert detect_module_load_abort("javascript", src) is None


def test_no_false_dead_scope_over_live_function_from_template_data():
    # The `if (false) {` on line 3 is template DATA; backdoor() is a
    # live top-level function (executes under node).
    src = (
        "const a = `${`}`}`;\n"
        "const b = `\n"
        "if (false) {\n"
        "`; // `\n"
        "function backdoor(req) { return req.q; }\n"
        "const c = `${`}`}`;\n"
        "const d = `\n"
        "}\n"
        "`; // `\n"
    )
    assert detect_dead_scopes("javascript", src) == []


def test_real_dead_scope_still_detected_after_nested_interpolation():
    # The conservative direction must not overcorrect: a genuine
    # if-false block AFTER a hostile-nesting template is still found.
    src = (
        'const x = `${"}"}ok`;\n'
        "if (false) {\n"
        "  dead();\n"
        "}\n"
    )
    assert detect_dead_scopes("javascript", src) == [(2, 4)]


# ---------------------------------------------------------------------------
# Regex-vs-division ambiguity: a candidate span carrying a quote or
# backtick must make the lexer REFUSE (whole-file bail), never blank.
# `x = {a:1} /`/;` is real division followed by a template opener; a
# `}`-preceded `/` reads as a regex candidate, and blanking `` /`/ ``
# swallows the backtick — template parity flips for the rest of the
# file. Both consumer fixtures below are node-verified: the files load
# and print, so any abort/dead-range over them is fabricated.
# ---------------------------------------------------------------------------


def test_quote_or_backtick_in_regex_candidate_raises():
    for delim in ("`", '"', "'"):
        src = "x = {a:1} /" + delim + "/;\n"
        with pytest.raises(JsLexAmbiguityError):
            blank_js_noncode(src)
    # Unambiguous position too — the contract is span-content-based,
    # not preceder-enumerated (`++`/`--`/keyword corners included).
    with pytest.raises(JsLexAmbiguityError):
        blank_js_noncode('var q = /"/;\n')


def test_backtick_swallowing_fake_regex_no_fabricated_abort():
    # node: prints `LOADED OK 42` — the throw is template DATA.
    src = (
        "x = {a:1} /`/;\n"
        "throw new Boom();\n"
        "`;\n"
        "function live() { return 42; }\n"
        'console.log("LOADED OK", live());\n'
    )
    assert detect_module_load_abort("javascript", src) is None


def test_backtick_swallowing_fake_regex_no_false_dead_range():
    # node: prints `LOADED OK 7` — backdoor() is live top-level code;
    # the `if (false) {` is template DATA.
    src = (
        "x = {a:1} /`/;\n"
        "if (false) {\n"
        "`;\n"
        "function backdoor() { return 7; }\n"
        "q = `}`;\n"
        'console.log("LOADED OK", backdoor());\n'
    )
    assert detect_dead_scopes("javascript", src) == []


def test_postfix_increment_fake_regex_bails_conservatively():
    # Same class through the `++` preceder (last significant char is
    # `+`, a regex-preceder): `i++ /`/;` is division by a template.
    src = (
        "let i = 2;\n"
        "let n = i++ /`/;\n"
        "throw new Boom();\n"
        "`;\n"
        "function live() { return 1; }\n"
    )
    assert detect_module_load_abort("javascript", src) is None
    assert detect_dead_scopes("javascript", src) == []
