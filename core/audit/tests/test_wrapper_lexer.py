"""Wrapper-path lexical views — sink lines can never be swallowed.

The trivial-wrapper skip judges two views cut by the shared
``sanitized_view`` chokepoint: the comments-only view (strings kept)
that the call/callee gates read, and the reference view (strings and
comments blanked) that the escape analysis and argument-position scan
read.  The invariant under test is directional and mechanical, and it
covers BOTH halves of the pipeline — the lexer and the line filter
that consumes it:

* string DATA — including every raw/template/backtick/text-block/
  heredoc/regex form and escaped quotes — can never open or close
  comment state in the scanner, so it can never blank a following
  sink out of the judged view;
* the post-lexer line filter judges drop-eligibility on the BLANKED
  twin only, where string data is spaces — so kept string data can
  never spell a droppable prefix and re-swallow the line (a
  multi-line literal continuation starting with ``//`` or ``#``
  whose closing line carries live code);
* constructs the scanner does not model keep their text in the
  judged view (over-inclusion — costs a review, never a swallow);
* prose in real comments/strings never flips a benign wrapper the
  other way (the legitimate skip corpus keeps skipping).

Shapes 1-4 are the filed false-suppression PoCs (C++ raw-string
desync; JS template / Go backtick continuation opening phantom
comment state; Rust raw string closing the per-line quote early);
shape 5 is the escape-blind string regex (a ``\\"`` inside a literal
swallowed the sink argument between two literals).  The remaining
classes pin the CONSUMER half of the seam — line-filter re-swallow
through kept string data, JS regex literals minting comment state
(modeled contexts lexed, ambiguous division contexts refused), and
the perl ``$#`` blanking shape.  The battery then walks each
language's string/comment grammar generatively.
"""

from __future__ import annotations

import random
import re

from core.audit.prefilter import _is_trivial_wrapper


def _refused(source: str, lang: str) -> bool:
    return not _is_trivial_wrapper(source, lang, None)[0]


class TestFiledPoCs:
    """The exact filed shapes, pinned one by one."""

    def test_cpp_raw_string_does_not_swallow_sink(self):
        src = (
            'int w(const char *c) {\n'
            '    helper(c, R"(a " b /* )");\n'
            '    system(c);\n'
            '    /* */ return 0;\n'
            '}'
        )
        assert _refused(src, "cpp")

    def test_cpp_raw_string_return_shape(self):
        src = (
            'int w(const char *c) {\n'
            '    helper(c, R"(a " b /* )");\n'
            '    return system(c);\n'
            '}'
        )
        assert _refused(src, "cpp")

    def test_js_template_continuation_does_not_swallow_sink(self):
        src = (
            'function wrap(cmd) {\n'
            '    const q = `data\n'
            '/* more data`;\n'
            '    return execSync(cmd);\n'
            '}'
        )
        assert _refused(src, "javascript")

    def test_go_backtick_continuation_does_not_swallow_sink(self):
        src = (
            'func Wrap(cmd string) {\n'
            '    q := `data\n'
            '/* more`\n'
            '    exec.Command(cmd)\n'
            '}'
        )
        assert _refused(src, "go")

    def test_rust_raw_string_does_not_swallow_sink(self):
        src = (
            'fn wrap(cmd: &str) {\n'
            '    let q = r#""/*"#;\n'
            '    Command::new(cmd);\n'
            '}'
        )
        assert _refused(src, "rust")

    def test_escaped_quote_does_not_swallow_sink_argument(self):
        # `"a\""` consumed as a complete literal made `", system, "`
        # the NEXT literal — the executor-argument sink reference was
        # stripped out of the judged reference view.
        src = (
            'int f(char *cmd) {\n'
            '    return dispatch("a\\"", system, "b");\n'
            '}'
        )
        assert _refused(src, "c")

    def test_escaped_quote_control_still_refuses(self):
        # The unescaped twin was already refused (sink-as-argument);
        # pin it so the pair moves together.
        src = (
            'int f(char *cmd) {\n'
            '    return dispatch("a", system, "b");\n'
            '}'
        )
        assert _refused(src, "c")


class TestLineFilterOnBlankedView:
    """The post-lexer line filter must judge drops on the blanked
    twin: in the comments-only view a line can start with ``//`` or
    ``#`` ONLY via kept string data (comments are already blanked),
    and dropping it swallowed live code sharing the line with a
    multi-line literal's closer."""

    def test_cpp_raw_continuation_slashes_do_not_drop_sink(self):
        src = (
            'int wrap(char *c) {\n'
            '    const char *x = R"(\n'
            '// hidden )"; system(c); const char *y = R"(\n'
            ')";\n'
            '    return helper(x, y);\n'
            '}'
        )
        assert _refused(src, "cpp")

    def test_cpp_raw_continuation_minimal_shape(self):
        src = 'int w(char *c) {\n    helper(c, R"(x\n// y)"); system(c);\n}'
        assert _refused(src, "cpp")

    def test_backslash_continued_string_does_not_drop_sink(self):
        src = 'int w(char *c) {\n    helper(c, "x\\\n// y"); system(c);\n}'
        assert _refused(src, "c")

    def test_hash_prefix_twin_does_not_drop_sink(self):
        src = 'int w(char *c) {\n    helper(c, R"(x\n# y)"); system(c);\n}'
        assert _refused(src, "cpp")

    def test_intended_drops_preserved(self):
        # Preprocessor lines and comment-only lines still drop; the
        # benign wrapper keeps its skip through both. The directive
        # carries a call-shaped capture (`defined(X)`) so the fixture
        # FLIPS if the #-drop arm dies: without the drop the capture
        # joins the judged body and the single-call gate refuses.
        skip, reason = _is_trivial_wrapper(
            "int f(char *c) {\n#if defined(X)\n    return helper(c);\n"
            "#endif\n}", "c", None)
        assert skip and "helper" in reason
        skip, reason = _is_trivial_wrapper(
            "int f(char *c) {\n    // note\n    return helper(c);\n}",
            "c", None)
        assert skip and "helper" in reason


class TestJsAmbiguousSlashRefusal:
    """A `/` right after `)` or `]` is the one js/ts spelling the
    lexer heuristic cannot decide (regex vs division) — and a regex
    interior there can mint comment state in code position, the full
    one-planted-line suppression primitive. The wrapper tier refuses
    the skip outright instead of judging it."""

    def test_ambiguous_context_regex_never_swallows_sink(self):
        src = (
            "const wrap = (c) => {\n"
            "  if (x) /\\//.test(c); fs.unlinkSync(c);\n"
            "  return helper(c);\n"
            "}"
        )
        assert _refused(src, "javascript")

    def test_division_after_paren_refuses_by_design(self):
        # The accepted cost, stated: a delegate carrying genuine
        # division in the ambiguous context goes to review instead
        # of skipping (refusal direction, one LLM review).
        src = (
            "const wrap = (c) => {\n"
            "  const y = (a + b) / n;\n"
            "  return helper(y);\n"
            "}"
        )
        assert _refused(src, "javascript")

    def test_invalid_slash_backslash_spelling_refused(self):
        # A backslash after a division-read `/` has no valid-JS
        # reading (only a would-be regex body reads it), so the
        # refusal costs nothing on legitimate code — adjacent
        # spelling.
        src = (
            "const wrap = (c) => {\n"
            '  const s = "x" /\\//; fs.unlinkSync(c);\n'
            "  return helper(s);\n"
            "}"
        )
        assert _refused(src, "javascript")

    def test_padded_backslash_spelling_refused(self):
        # The backslash need not be adjacent to the slash — anywhere
        # later on the same ref-view line marks the invalid division
        # reading.
        src = (
            "const wrap = (c) => {\n"
            "  const s = a /x\\//; fs.unlinkSync(c);\n"
            "  return helper(s);\n"
            "}"
        )
        assert _refused(src, "javascript")

    def test_bracket_slash_refused_via_ambiguous_gate(self):
        # Boundary control: `]` before `/` trips the ambiguous-
        # context gate, not the backslash gate.
        src = (
            "const wrap = (c) => {\n"
            "  const s = a /x[/]//; fs.unlinkSync(c);\n"
            "  return helper(s);\n"
            "}"
        )
        assert _refused(src, "javascript")

    def test_char_class_after_paren_gate_discriminating_fixture(self):
        # Gate-discriminating shape: a char class right after `)` —
        # the one context ONLY the ambiguous-slash gate covers (no
        # backslash for the backslash gate, no pointer-arith spelling,
        # no other refusal applies). With the gate regressed this
        # shape SKIPS and the one-planted-line suppression primitive
        # re-opens; every other slash fixture in this battery is
        # co-refused by an unrelated gate and cannot see that
        # regression.
        src = (
            "const wrap = (c) => {\n"
            "  if (x) /[//]y/.test(c); fs.unlinkSync(c);\n"
            "  return helper(c);\n"
            "}"
        )
        assert _refused(src, "javascript")

    def test_ambiguous_gate_kills_its_own_mutant(self, monkeypatch):
        # Discrimination proved in-process: with the gate disabled
        # the fixture above flips to a skip. A refactor deleting or
        # weakening _JS_AMBIGUOUS_SLASH_RE now fails THIS battery
        # instead of staying green on co-refused fixtures.
        import core.audit.prefilter as pf
        src = (
            "const wrap = (c) => {\n"
            "  if (x) /[//]y/.test(c); fs.unlinkSync(c);\n"
            "  return helper(c);\n"
            "}"
        )
        assert _refused(src, "javascript")
        monkeypatch.setattr(
            pf, "_JS_AMBIGUOUS_SLASH_RE", re.compile(r"(?!x)x"),
        )
        skip, _ = pf._is_trivial_wrapper(src, "javascript", None)
        assert skip, (
            "fixture no longer gate-discriminating — another gate "
            "co-refuses it; replace with a shape only the "
            "ambiguous-slash gate covers"
        )

    def test_char_class_comment_mint_known_direction_pin(self):
        # DECLARED OPEN residual (suppression direction, js/ts
        # wrapper delegates only): a would-be regex body can hide a
        # comment-opener with NO backslash — `a /[//]x/` puts the
        # `//` in a char class, the division reading dies only on a
        # later line (unterminated `[`), and everything after the
        # `//` blanks out of both views. No zero-cost spelling rule
        # closes this (refusing division-then-`//` would flip every
        # `a / b; // note` delegate — see the control below); the
        # honest fix is parser-grade JS lexing. Pinned so any
        # behavior change is visible.
        src = (
            "const wrap = (c) => {\n"
            "  const s = a /[//]x/; fs.unlinkSync(c);\n"
            "  return helper(s);\n"
            "}"
        )
        skip, _ = _is_trivial_wrapper(src, "javascript", None)
        assert skip, "known-direction residual changed — update NOTES"

    def test_division_with_trailing_comment_still_skips(self):
        # The control that proves the residual is not closeable by
        # refusing division-then-`//`: a genuine comment after
        # division is routine legitimate code and must keep its skip.
        src = (
            "const wrap = (c) => {\n"
            "  const y = a / b; // note\n"
            "  return helper(y);\n"
            "}"
        )
        skip, reason = _is_trivial_wrapper(src, "javascript", None)
        assert skip
        assert "helper" in reason

    def test_escaped_slash_in_modeled_regex_not_refused(self):
        # Legit control: an escaped slash INSIDE a value-position
        # regex is handled by the regex arm (interior blanked before
        # the refusal scans), so the delegate keeps its skip.
        src = (
            "const wrap = (c) => {\n"
            "  const re = /a\\/b/;\n"
            "  return helper(re);\n"
            "}"
        )
        skip, reason = _is_trivial_wrapper(src, "javascript", None)
        assert skip
        assert "helper" in reason

    def test_unambiguous_division_delegate_still_skips(self):
        # Precision pin: division after an identifier is decidable,
        # so the refusal does not fire and the benign delegate keeps
        # its skip end to end.
        src = (
            "const wrap = (c) => {\n"
            "  const y = a / b;\n"
            "  return helper(y);\n"
            "}"
        )
        skip, reason = _is_trivial_wrapper(src, "javascript", None)
        assert skip
        assert "helper" in reason


class TestTemplateInterpolationValueEscape:
    """A dangerous reference escaping as a `${…}` interpolation VALUE
    must be judged: the statement split fragments the binding into an
    empty-ref assignment plus an expression fragment, and pre-fix the
    fragment's refs were returned unjudged — a one-line hostile plant
    journalled mechanically clean while fully visible in both judged
    views. Expression fragments now join the value-escape judgment
    (over-exclusion costs a review — the file's stated doctrine)."""

    def test_template_value_escape_refused(self):
        # The filed shape: `execSync` escapes as an interpolation
        # value, no call parentheses anywhere near it.
        src = (
            "const g = (c) => {\n"
            "  const t = `${x && execSync}`;\n"
            "  return helper(t, c);\n"
            "}"
        )
        assert _refused(src, "javascript")

    def test_non_template_control_refused(self):
        # Identical escape without the template — the shape the
        # analysis always caught; pins that both spellings agree.
        src = (
            "const g = (c) => {\n"
            "  const t = x && execSync;\n"
            "  return helper(t, c);\n"
            "}"
        )
        assert _refused(src, "javascript")

    def test_benign_interpolation_keeps_skip(self):
        # Cost control: a data-only interpolation still skips.
        src = (
            "const g = (c) => {\n"
            "  const t = `${prefix}-suffix`;\n"
            "  return helper(t, c);\n"
            "}"
        )
        assert not _refused(src, "javascript")

    def test_expression_statement_escape_refused(self):
        # The general member behind the template shape: a bare
        # expression statement carrying a dangerous ref is a value
        # escape too.
        src = (
            "const g = (c) => {\n"
            "  x && execSync;\n"
            "  return helper(c);\n"
            "}"
        )
        assert _refused(src, "javascript")


class TestJsRegexCommentMint:
    """A JS regex literal whose interior spells ``//`` or ``/*`` must
    not mint comment state in code position (the kept view is the one
    that feeds the call gates — blanking there IS the swallow)."""

    def test_escaped_slash_regex_does_not_swallow_sink(self):
        src = (
            "const wrap = (c) => {\n"
            "  const re = /\\//; fs.unlinkSync(c);\n"
            "  return helper(re);\n"
            "}"
        )
        assert _refused(src, "javascript")

    def test_slash_star_regex_does_not_open_block_comment(self):
        src = (
            "const wrap = (c) => {\n"
            "  const re = /\\/*/ ;\n"
            "  fs.unlinkSync(c);\n"
            "  return helper(re);\n"
            "}"
        )
        assert _refused(src, "javascript")


class TestPerlLuaLineFilter:
    """The perl/lua branch must not drop lines by raw text prefix:
    the scanner does not model every perl quote construct (plain
    ``"…"`` spans lines, q//, qq{}, heredocs), so no view can DECIDE
    that a ``#``-prefixed line is a comment — a multi-line string's
    continuation line can start with ``#`` (string data) and carry
    live code after the closing quote. Comment-looking lines stay in
    the judged view (over-inclusion — costs a review, never a
    swallow); only blank lines and lone braces drop."""

    def test_perl_string_continuation_hash_does_not_drop_sink(self):
        # The line `# b"; system($cmd);` is string data + live code
        # (perl double-quoted strings are multi-line). The raw `#`
        # prefix filter dropped it from BOTH judged views — `system(`
        # was invisible to the call-count, callee, and escape layers
        # and the delegate journalled mechanically clean.
        src = (
            'sub wrap {\n'
            ' my $t = "a\n'
            '# b"; system($cmd);\n'
            ' return helper(@_);\n'
            '}'
        )
        assert _refused(src, "perl")

    def test_lua_long_string_continuation_hash_does_not_drop_sink(self):
        # Lua long strings ARE modeled, but the raw filter dropped a
        # continuation line starting with `#` regardless — string
        # data spelled a droppable prefix in an unblanked view.
        src = (
            'function wrap(c)\n'
            ' local t = [[a\n'
            '# b]] os.execute(c)\n'
            ' return helper(c)\n'
            'end'
        )
        assert _refused(src, "lua")

    def test_perl_typeglob_alias_not_dropped_as_comment(self):
        # `*alias = \\&CORE::system;` is live sink-aliasing code; the
        # `*` prefix arm dropped it as a block-comment continuation.
        src = (
            'sub wrap {\n'
            '*alias = \\&CORE::system;\n'
            ' return helper(@_);\n'
            '}'
        )
        assert _refused(src, "perl")

    def test_benign_perl_wrapper_keeps_skip(self):
        skip, reason = _is_trivial_wrapper(
            'sub wrap {\n return helper(@_);\n}', "perl", None)
        assert skip and "helper" in reason

    def test_prose_comment_keeps_skip(self):
        # A genuine comment WITHOUT a call shape stays skip-eligible:
        # kept lines only cost the skip when they add call-shaped or
        # dangerous text, or push the wrapper over the line cap.
        skip, reason = _is_trivial_wrapper(
            'sub wrap {\n # forwards to the helper\n'
            ' return helper(@_);\n}', "perl", None)
        assert skip and "helper" in reason

    def test_call_shaped_comment_refuses_documented_direction(self):
        # A comment spelling `name(…)` reads as a second call and
        # refuses the skip — over-inclusion costs one review, the
        # documented safe direction. Two-direction pin (see
        # test_prose_comment_keeps_skip for the keep side) so a
        # future re-tightening of the drop filter is visible here.
        assert _refused(
            'sub wrap {\n # calls helper() twice\n'
            ' return helper(@_);\n}', "perl")

    def test_perl_exotic_terminator_does_not_desync_ref_view(self):
        # A lone \r inside string data used to split raw_lines one
        # ahead of the ref view, pairing the escape scan with the
        # wrong source lines. Normalised before the views split (the
        # C-family branch discipline); the sink-bearing wrapper must
        # refuse with the terminator present exactly as without it.
        src = (
            'sub wrap {\n'
            ' my $t = "a\rb";\n'
            ' dispatch($c, \\&system);\n'
            '}'
        )
        assert _refused(src, "perl")


class TestPerlSigilHash:
    """``$#`` is code (array last-index), not a comment opener —
    blanking from it swallowed a sink-as-argument reference out of
    the exact gate the escaped-quote C PoC protects."""

    def test_dollar_hash_does_not_swallow_sink_argument(self):
        src = "sub w {\n    my $n = $#arr; dispatch($c, \\&system);\n}"
        assert _refused(src, "perl")

    def test_hash_in_perl_regex_known_direction_pin(self):
        # DECLARED residual (suppression direction, perl aux layers
        # only): a `#` inside an unmodeled perl quote-construct
        # (m/x#y/) still blanks the rest of the REF-view line, hiding
        # a sink-as-argument reference from the argument scan. Pinned
        # so any behavior change is visible; the honest fix is a perl
        # quote-op grammar, out of this series' charter.
        src = "sub w {\n    my $r = m/x#y/; dispatch($c, \\&system);\n}"
        skip, _ = _is_trivial_wrapper(src, "perl", None)
        assert skip, "known-direction residual changed — update NOTES"


class TestLuaAccessorGate:
    def test_sink_reference_return_is_not_an_accessor(self):
        from pathlib import Path

        from core.audit.prefilter import run_prefilter
        r = run_prefilter(
            target_path=Path("/tmp"), file_path="obj.lua",
            function_name="get",
            source="function get(x)\n    return os.execute\nend",
            line_start=1,
        )
        assert not r.skip_llm

    def test_benign_field_and_constant_returns_still_skip(self):
        from pathlib import Path

        from core.audit.prefilter import run_prefilter
        for body in ("return self.value", "return 42"):
            r = run_prefilter(
                target_path=Path("/tmp"), file_path="obj.lua",
                function_name="get",
                source=f"function get(x)\n    {body}\nend",
                line_start=1,
            )
            assert r.skip_llm, body
            assert "accessor" in r.skip_reason


class TestSelfCapture:
    """The signature's own name must never be the 'one call' — a
    signature-only view (the shape a desynced lexer degrades to) is
    never mechanically clean, and a healthy wrapper's reason never
    names the wrapper itself."""

    def test_signature_only_go_body_refused(self):
        assert _refused("func Wrap(c string) {\n}\n", "go")

    def test_signature_only_rust_body_refused(self):
        assert _refused("fn wrap(c: &str) {\n}\n", "rust")

    def test_signature_only_js_body_refused(self):
        assert _refused("function wrap(c) {\n}\n", "javascript")

    def test_one_call_brace_language_bodies_refuse(self):
        # The signature capture makes these 2-capture bodies, and the
        # self-capture guard closes the degraded 1-capture shape — so
        # go/rust delegates refuse outright (over-refusal by design,
        # documented). Pinned as REFUSALS: a previous spelling of this
        # control asserted on the reason only when skip was granted,
        # which never executed (vacuous at both trees).
        for src, lang in [
            ("func Wrap(c string) {\n    helper(c)\n}\n", "go"),
            ("fn wrap(c: &str) {\n    helper(c);\n}\n", "rust"),
        ]:
            assert _refused(src, lang), (src, lang)

    def test_reason_names_the_delegate_not_the_wrapper(self):
        # The reason invariant, pinned on a shape that actually
        # SKIPS: the c/cpp delegate's reason must name the callee,
        # never the wrapper's own name.
        skip, reason = _is_trivial_wrapper(
            "int wrap(char *c) {\n    return helper(c);\n}\n", "c", None)
        assert skip
        assert "helper" in reason
        assert "wrap(" not in reason

    def test_lua_accessor_skips_via_accessor_gate_not_wrapper(self):
        # The legitimate no-call shape keeps its skip through the
        # honest accessor arm, not the self-capture.
        from pathlib import Path

        from core.audit.prefilter import run_prefilter
        r = run_prefilter(
            target_path=Path("/tmp"), file_path="obj.lua",
            function_name="get_value",
            source="function get_value(self)\n    return self.value\nend",
            line_start=1,
        )
        assert r.skip_llm
        assert "accessor" in r.skip_reason


# ── Generative battery over the language grammar set ──────────────
#
# For each language: adversarial NOISE constructs drawn from its real
# string/comment grammar (each containing a `/*` marker, a quote, or
# an escape that desynced the old per-line lexer), composed 1-3 at a
# time ahead of a live sink line inside a delegate-looking body. The
# oracle is refusal: the sink line must stay in the judged view.

_SINK = {
    "c": "    system(c);",
    "cpp": "    system(c);",
    "go": "    exec.Command(c)",
    "rust": "    Command::new(c);",
    "javascript": "    execSync(c);",
    "typescript": "    execSync(c);",
    "java": "    Runtime.getRuntime().exec(c);",
    "php": "    system($c);",
    "lua": "    os.execute(c)",
    "perl": "    system($c);",
}

_HEAD = {
    "c": "int w(char *c) {",
    "cpp": "int w(char *c) {",
    "go": "func w(c string) {",
    "rust": "fn w(c: &str) {",
    "javascript": "function w(c) {",
    "typescript": "function w(c) {",
    "java": "void w(String c) {",
    "php": "function w($c) {",
    "lua": "function w(c)",
    "perl": "sub w {",
}

_TAIL = {"lua": "end"}

_NOISE = {
    "c": [
        '    helper(c, "a\\"");',
        '    helper(c, "x /* y");',
        "    helper(c, 'x');",
        '    /* opener\n    prose " with quote\n    */ helper(c);',
        '    helper(c); // trailing /* prose',
    ],
    "cpp": [
        '    helper(c, R"(a " b /* )");',
        '    helper(c, R"x(quote " and )" here /* )x");',
        '    helper(c, u8R"(data /* )");',
        '    helper(c, LR"(w /* )");',
        '    helper(c, "a\\"");',
        '    helper(c, R"(line one\n" /* line two\n)");',
    ],
    "go": [
        '    q := `raw\n/* continuation`',
        '    q := `has " quote /* marker`',
        '    helper(c, "a\\"")',
        "    r := 'x'",
    ],
    "rust": [
        '    let q = r#""/*"#;',
        '    let q = r"plain /* raw";',
        '    let q = br#"bytes " /* "#;',
        '    let q = r##"deep "# /* "##;',
        "    let l: &'static str = \"x /* y\";",
        '    let q = "a\\"";',
    ],
    "javascript": [
        '    const q = `data\n/* continuation`;',
        '    const q = `escaped \\` tick /* still`;',
        "    const q = 'a\\'';",
        '    const q = "a\\"";',
        '    const q = `pre ${1} /* post`;',
    ],
    "typescript": [
        '    const q = `data\n/* continuation`;',
        '    const q = "a\\"";',
    ],
    "java": [
        '    String q = """\n    text /* block " prose\n    """;',
        '    String q = "a\\"";',
        "    char x = 'y';",
    ],
    "php": [
        '    $q = <<<EOT\nbody /* prose " here\nEOT;',
        "    $q = <<<'EOT'\nnowdoc /* prose\nEOT;",
        '    $q = "a\\"";',
        '    $q = 1; # trailing /* prose',
    ],
    "lua": [
        '    local q = [[long -- string /* prose]]',
        '    local q = [=[leveled ]] still -- /* ]=]',
        '    local q = "a\\""',
        '    local q = 1 -- trailing /* prose',
    ],
    "perl": [
        '    my $q = "a\\"";',
        "    my $q = 'x # y';",
        '    my $q = 1; # trailing prose',
    ],
}


class TestGenerativeGrammarBattery:
    def test_sink_after_noise_always_refuses(self):
        rng = random.Random("wrapper-lexer-battery")
        for lang, fragments in _NOISE.items():
            shapes = [[f] for f in fragments]
            for _ in range(12):
                k = rng.randint(1, 3)
                shapes.append([rng.choice(fragments) for _ in range(k)])
            for shape in shapes:
                body = [_HEAD[lang], *shape, _SINK[lang]]
                tail = _TAIL.get(lang, "}")
                src = "\n".join(body) + "\n" + tail + "\n"
                skip, reason = _is_trivial_wrapper(src, lang, None)
                assert not skip, (
                    f"{lang}: sink swallowed behind {shape!r} "
                    f"(reason={reason!r})"
                )

    def test_benign_noise_keeps_c_family_skip(self):
        # The other direction: a legitimate one-call delegate whose
        # string/comment noise carries the same markers still earns
        # the skip (prose must not flip benign wrappers to review
        # when the delegate itself is clean and single-call).
        for src in (
            'int w(char *c) {\n    return helper(c); /* done /* */\n}\n',
            'int w(char *c) {\n    return helper(c); // note /* x\n}\n',
        ):
            skip, reason = _is_trivial_wrapper(src, "c", None)
            assert skip, (src, reason)
            assert "helper" in reason


class TestSplitlinesTerminatorUniverse:
    """The kept/blanked view pair must agree on what a line IS.

    ``str.splitlines`` splits on more than the universal-newlines set
    (\\x0b \\x0c \\x1c-\\x1e \\x85 U+2028/9).  A terminator the
    normalisation list missed survives as string DATA in the kept
    view but blanks to a space in the ref view, so the kept view
    gains a line, every later pair is off by one, and the
    drop-eligibility check judges a live sink line against the wrong
    blanked twin — one plantable byte re-opens the one-planted-line
    skip.  The views now split on ``\\n`` only, after one shared
    normalisation whose members are DERIVED from splitlines itself.
    """

    #: every splitlines-splitting byte a string literal can carry
    _EXOTIC = ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e",
               "\x85", "\u2028", "\u2029")

    def test_vt_in_string_does_not_mint_wrapper_skip(self):
        # The filed shape: a \x0b inside a string literal swallowed
        # the system(c) line from both judged views.
        src = ('int wrap(char *c) {\n  const char *s = "A\x0bB";\n'
               '  system(c);\n#define X 1\n  return helper(c);\n}')
        assert _refused(src, "c")

    def test_every_exotic_terminator_refuses_the_sink_wrapper(self):
        for term in self._EXOTIC:
            src = (f'int wrap(char *c) {{\n  const char *s = "A{term}B";\n'
                   f'  system(c);\n#define X 1\n  return helper(c);\n}}')
            assert _refused(src, "c"), f"desync via {term!r}"

    def test_exotic_terminator_perl_branch_refuses_too(self):
        for term in self._EXOTIC:
            src = (f'sub wrap {{\n my $t = "a{term}#";\n'
                   f' system($c);\n return helper($c);\n}}')
            assert _refused(src, "perl"), f"desync via {term!r}"

    def test_normalisation_set_matches_splitlines_universe(self):
        # Two-direction closure, derived from the splitting authority
        # itself: (1) every char splitlines splits on is either \n or
        # a member of the normalisation tuple; (2) every single-char
        # member really splits (no stale members).  Chunked scan over
        # the full codepoint space keeps this fast.
        from core.audit.prefilter import _LINE_TERMINATORS

        derived: set[str] = set()
        cps = [chr(cp) for cp in range(0x110000)
               if not 0xD800 <= cp <= 0xDFFF]
        for i in range(0, len(cps), 4096):
            chunk = cps[i:i + 4096]
            probe = "a".join(chunk)
            if len(probe.splitlines()) == 1:
                continue
            derived.update(c for c in chunk
                           if len(f"a{c}b".splitlines()) > 1)
        singles = {t for t in _LINE_TERMINATORS if len(t) == 1}
        assert derived - {"\n"} == singles
        assert "\r\n" in _LINE_TERMINATORS

    def test_benign_wrapper_with_exotic_string_data_direction(self):
        # Direction pin: the normalisation splits the literal's data
        # across lines, leaving an unterminated-string reading — the
        # documented over-inclusion direction (costs one review).  A
        # terminator-free twin keeps its skip.
        skip, reason = _is_trivial_wrapper(
            'int w(char *c) {\n  return helper(c);\n}\n', "c", None)
        assert skip and "helper" in reason
