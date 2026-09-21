"""Tests for the tokenizer-grade non-code blanker
(:mod:`core.inventory.lexical_view`).

Grammar-dependent tests skip when the language's tree-sitter wheel is
absent; the degradation tests (grammar missing → ``None``) run
everywhere.
"""

from __future__ import annotations

import pytest

from core.inventory import lexical_view
from core.inventory.lexical_view import (
    NONCODE_NODE_MODES,
    LexicalRefusal,
    blank_noncode,
)


def _grammar_available(language: str) -> bool:
    return lexical_view._language_for(language) is not None


def _requires(language: str) -> None:
    if not _grammar_available(language):
        pytest.skip(f"{language} tree-sitter grammar not installed")


# ---------------------------------------------------------------------------
# Node-type closure: every table entry must be producible by the
# installed grammar. A dead or renamed entry silently stops blanking
# its lexical class — the false-suppression direction — so it must
# fail here, not in production.
#
# Skip gating: on the GRAMMAR MODULE import only, never on
# ``_language_for`` — runtime validation returns ``None`` for both
# grammar-absent AND table drift, and drift is exactly the condition
# this oracle exists to FAIL on. Gating on it would turn every drifted
# table into a green skip ("grammar not installed") while the runtime
# silently disabled the language's witnesses.
# ---------------------------------------------------------------------------


def _grammar_language(language: str):
    """The raw grammar Language for the closure oracle, or ``None``
    only when the grammar module (or tree_sitter) is truly absent —
    deliberately independent of the runtime validation cache."""
    try:
        import tree_sitter
    except ModuleNotFoundError:
        return None
    module_name, attr = lexical_view._GRAMMARS[language]
    mod = lexical_view._ts_cache.import_grammar(module_name)
    if mod is None:
        return None
    return tree_sitter.Language(getattr(mod, attr)())


def _missing_node_kinds(language, lang) -> list[str]:
    return [
        name for name in NONCODE_NODE_MODES[language]
        if not lang.id_for_node_kind(name, True)
    ]


@pytest.mark.parametrize("language", sorted(NONCODE_NODE_MODES))
def test_every_table_node_type_exists_in_grammar(language):
    lang = _grammar_language(language)
    if lang is None:
        pytest.skip(f"{language} tree-sitter grammar module not installed")
    missing = _missing_node_kinds(language, lang)
    assert missing == [], (
        f"{language}: table entries the grammar cannot produce "
        f"(dead entries / grammar rename): {missing}"
    )


@pytest.mark.parametrize("language", sorted(NONCODE_NODE_MODES))
def test_closure_oracle_fails_on_planted_drift(language, monkeypatch):
    """Negative control: planted table drift must be REPORTED by the
    closure computation — it must never read as grammar-absent (a
    skip would leave CI green while the runtime disabled the
    language's witnesses on every deployment)."""
    lang = _grammar_language(language)
    if lang is None:
        pytest.skip(f"{language} tree-sitter grammar module not installed")
    monkeypatch.setitem(
        NONCODE_NODE_MODES[language], "planted_drift_kind", "all",
    )
    assert "planted_drift_kind" in _missing_node_kinds(language, lang)


# ---------------------------------------------------------------------------
# Completeness oracle: the closure test above only proves LISTED names
# producible (the dead-entry direction). The completeness oracle closes
# the LIVE direction — every prose-named node kind the grammar can
# produce must be classified (blanked or reviewed-exempt), else its
# content survives into the "code" view (``hash_bang_line`` did, and a
# one-line JS hashbang minted a whole-file module-load abort).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("language", sorted(NONCODE_NODE_MODES))
def test_prose_kind_completeness(language):
    lang = _grammar_language(language)
    if lang is None:
        pytest.skip(f"{language} tree-sitter grammar module not installed")
    gap = lexical_view._prose_completeness_gap(language, lang)
    assert gap == [], (
        f"{language}: grammar-producible prose node kinds neither "
        f"blanked nor reviewed-exempt: {gap}"
    )


@pytest.mark.parametrize("language", sorted(NONCODE_NODE_MODES))
def test_completeness_oracle_fails_on_planted_gap(language, monkeypatch):
    """Negative control (mutation check of the oracle itself): drop a
    prose-named table entry and the gap computation must REPORT it —
    never read the shrunken table as complete."""
    lang = _grammar_language(language)
    if lang is None:
        pytest.skip(f"{language} tree-sitter grammar module not installed")
    victim = next(
        k for k in NONCODE_NODE_MODES[language]
        if lexical_view._PROSE_KIND_RE.search(k)
    )
    monkeypatch.delitem(NONCODE_NODE_MODES[language], victim)
    assert victim in lexical_view._prose_completeness_gap(language, lang)


@pytest.mark.parametrize(("language", "kind"), [
    ("php", "shell_command_expression"),
    ("ruby", "subshell"),
])
def test_backtick_command_kinds_are_oracle_covered(
        language, kind, monkeypatch):
    """Mutation control for the backtick command literals: these two
    kinds carry full attacker-authored shell command text, and their
    names match no obvious prose noun — dropping either table line
    must FAIL the completeness oracle, never leave every suite green
    while the command content leaks verbatim into the code view."""
    assert lexical_view._PROSE_KIND_RE.search(kind), (
        f"{kind}: not in the prose pattern's net — the oracle cannot "
        f"see this kind at all"
    )
    lang = _grammar_language(language)
    if lang is None:
        pytest.skip(f"{language} tree-sitter grammar module not installed")
    monkeypatch.delitem(NONCODE_NODE_MODES[language], kind)
    assert kind in lexical_view._prose_completeness_gap(language, lang)


@pytest.mark.parametrize("language", sorted(NONCODE_NODE_MODES))
def test_exempt_kinds_are_producible_and_disjoint_from_table(language):
    """Exempt-list hygiene: a dead exempt entry is cruft that could
    mask a future rename; a table/exempt overlap would make the
    classification ambiguous."""
    exempt = lexical_view._PROSE_EXEMPT_KINDS[language]
    assert not (exempt & set(NONCODE_NODE_MODES[language]))
    lang = _grammar_language(language)
    if lang is None:
        pytest.skip(f"{language} tree-sitter grammar module not installed")
    dead = [k for k in sorted(exempt) if not lang.id_for_node_kind(k, True)]
    assert dead == [], (
        f"{language}: exempt entries the grammar cannot produce: {dead}"
    )


def test_every_language_has_exempt_set():
    assert set(lexical_view._PROSE_EXEMPT_KINDS) == set(NONCODE_NODE_MODES)


def test_runtime_disables_language_on_completeness_gap(monkeypatch):
    """The degrade direction stays NOT-suppress: an unclassified prose
    kind at runtime disables the language (``None`` — consumers bail,
    no witness), never a partial view."""
    _requires("javascript")
    monkeypatch.setattr(lexical_view, "_VALIDATED", {})
    monkeypatch.delitem(
        lexical_view.NONCODE_NODE_MODES["javascript"], "hash_bang_line",
    )
    try:
        assert blank_noncode("javascript", "x = 1;") is None
    finally:
        lexical_view._VALIDATED.clear()


def test_every_language_has_grammar_route_and_table():
    assert set(NONCODE_NODE_MODES) == set(lexical_view._GRAMMARS)
    for language, modes in NONCODE_NODE_MODES.items():
        assert modes, language
        assert set(modes.values()) <= {"all", "edges"}, language


# ---------------------------------------------------------------------------
# Fail-closed degradation
# ---------------------------------------------------------------------------


def test_unknown_language_returns_none():
    assert blank_noncode("cobol", "x = 1") is None


def test_missing_grammar_returns_none(monkeypatch):
    monkeypatch.setattr(
        lexical_view._ts_cache, "import_grammar", lambda name: None,
    )
    monkeypatch.setattr(lexical_view, "_VALIDATED", {})
    assert blank_noncode("javascript", "if (false) { x(); }") is None


def test_table_drift_disables_language(monkeypatch):
    """A node type the grammar cannot produce disables the language
    (fail closed) instead of silently un-blanking that class."""
    _requires("javascript")
    monkeypatch.setattr(lexical_view, "_VALIDATED", {})
    monkeypatch.setitem(
        lexical_view.NONCODE_NODE_MODES["javascript"],
        "renamed_by_grammar_upgrade", "all",
    )
    try:
        assert blank_noncode("javascript", "x = 1;") is None
    finally:
        del lexical_view.NONCODE_NODE_MODES["javascript"][
            "renamed_by_grammar_upgrade"]
        lexical_view._VALIDATED.clear()


def test_parse_error_raises_refusal():
    _requires("javascript")
    with pytest.raises(LexicalRefusal):
        blank_noncode("javascript", "function f( {")


def test_rust_parse_error_raises_refusal():
    _requires("rust")
    with pytest.raises(LexicalRefusal):
        blank_noncode("rust", "fn f( { let x = ;")


# ---------------------------------------------------------------------------
# Blanking semantics (line preservation, modes)
# ---------------------------------------------------------------------------


def test_js_comment_string_template_regex_blanked_code_kept():
    _requires("javascript")
    src = (
        'let a = "if (false) {"; // if (false) {\n'
        "let r = /if \\(false\\) \\{/;\n"
        "let t = `if (false) {`;\n"
        "if (false) { dead(); }\n"
    )
    out = blank_noncode("javascript", src)
    assert out is not None
    assert out.count("\n") == src.count("\n")
    assert len(out) == len(src)  # ASCII input: byte-stable
    # Only the REAL guard survives.
    assert out.count("if (false) {") == 1
    assert "dead();" in out
    # Delimiters survive (edges mode), contents do not.
    lines = out.split("\n")
    assert lines[0].startswith('let a = "')
    assert '"' in lines[0][9:]


def test_js_division_vs_regex_disambiguated_by_grammar():
    _requires("javascript")
    # Real division after an object literal — the `/` must NOT open a
    # regex that swallows the comment opener (the comment tail would
    # then lex as code).
    src = "x = {a:1} /2; // don`t\nlet y = 3;\n"
    out = blank_noncode("javascript", src)
    assert "/2;" in out
    assert "don" not in out
    # Real regex after an unbraced if header — must blank as a regex,
    # not read as division (its backtick would open a phantom template).
    src2 = "if (a) /x`y/.test(b);\nlet z = `code ${1}`;\n"
    out2 = blank_noncode("javascript", src2)
    assert "`y" not in out2
    assert ".test(b);" in out2


def test_js_template_interpolation_blanked_with_literal():
    _requires("javascript")
    src = "let t = `a ${ {b: '}'} } c`;\nlive();\n"
    out = blank_noncode("javascript", src)
    assert "live();" in out
    assert "{b:" not in out


def test_tsx_jsx_text_blanked():
    _requires("tsx")
    src = "const x = <div>if (false) {'{'}</div>;\nlive();\n"
    out = blank_noncode("tsx", src)
    assert "if (false)" not in out
    assert "live();" in out


@pytest.mark.parametrize("language", ["typescript", "tsx"])
def test_ts_template_literal_type_blanked(language):
    """Type-level template literal text is erased at compile time; its
    content must never survive into the code view (a hostile literal
    can otherwise place abort/dead-guard text at apparent depth 0)."""
    _requires(language)
    src = (
        "type T = `\n"
        'x;throw new Error("q");\n'
        "`;\n"
        "function live() { return 1; }\n"
    )
    out = blank_noncode(language, src)
    assert out is not None
    assert "throw" not in out
    assert "function live()" in out
    assert out.count("\n") == src.count("\n")


@pytest.mark.parametrize("language", ["javascript", "typescript", "tsx"])
def test_js_family_hashbang_blanked(language):
    """A hashbang is a legal, idiomatic first line whose text parses
    clean — unblanked it sits at apparent depth 0 of the code view."""
    _requires(language)
    src = (
        "#!/usr/bin/env node; throw new Boom(1)\n"
        "function live() { work(); }\n"
    )
    out = blank_noncode(language, src)
    assert out is not None
    assert "throw" not in out
    assert "node" not in out
    assert "function live() { work(); }" in out
    assert out.count("\n") == src.count("\n")


def test_rust_shebang_blanked():
    _requires("rust")
    src = '#!/usr/bin/env run-cargo-script "unbalanced\nfn live() {}\n'
    out = blank_noncode("rust", src)
    assert out is not None
    assert "cargo" not in out
    assert '"' not in out
    assert "fn live() {}" in out
    assert out.count("\n") == src.count("\n")


def test_memoized_view_is_stable_and_shared():
    _requires("javascript")
    src = "let a = 1; // if (false) {\nlive();\n"
    first = blank_noncode("javascript", src)
    second = blank_noncode("javascript", src)
    assert first == second


def test_memo_never_serves_stale_view_across_revalidation():
    """The memo key binds the validated Language object: after a
    revalidation that disables the language (drift), a previously
    cached view for the same content must not be served."""
    _requires("javascript")
    src = "x = 1; // note\n"
    assert blank_noncode("javascript", src) is not None  # cached
    lexical_view._VALIDATED.pop("javascript", None)
    lexical_view.NONCODE_NODE_MODES["javascript"]["planted_drift_kind"] = "all"
    try:
        assert blank_noncode("javascript", src) is None
    finally:
        del lexical_view.NONCODE_NODE_MODES["javascript"]["planted_drift_kind"]
        lexical_view._VALIDATED.pop("javascript", None)
    assert blank_noncode("javascript", src) is not None


def test_rust_comments_and_strings_blanked():
    _requires("rust")
    src = (
        "fn f() { // if false {\n"
        '  let s = "compile_error!(x)";\n'
        '  let r = r#"if false { raw"#;\n'
        "  /* nested /* if false { */ */\n"
        "  live();\n"
        "}\n"
    )
    out = blank_noncode("rust", src)
    assert "if false {" not in out
    assert "compile_error" not in out
    assert "live();" in out
    assert out.count("\n") == src.count("\n")


def test_ruby_heredoc_and_string_blanked_delimiters_kept():
    _requires("ruby")
    src = (
        "msg = <<~EOT\n  raise the alarm\n  if false\nEOT\n"
        'x = "exit\nnow"\n'
        "# comment raise\n"
        "live_call\n"
    )
    out = blank_noncode("ruby", src)
    assert "raise the alarm" not in out
    assert "if false" not in out
    assert "exit" not in out
    assert "comment" not in out
    assert "live_call" in out
    # Value-position evidence survives: the heredoc opener token and
    # the string's quotes are still on the code line.
    assert "<<~EOT" in out
    assert 'x = "' in out


def test_php_heredoc_nowdoc_html_blanked():
    _requires("php")
    src = (
        "<html>die</html><?php\n"
        "$a = <<<EOT\ndie\nEOT;\n"
        "$b = <<<'NOW'\nexit\nNOW;\n"
        '$c = "die $x";\n'
        "// die\n"
        "live();\n"
    )
    out = blank_noncode("php", src)
    assert "die" not in out
    assert "exit" not in out
    assert "<html>" not in out
    assert "live();" in out
    assert out.count("\n") == src.count("\n")


# ---------------------------------------------------------------------------
# Edges mode: surviving bytes must form a BALANCED delimiter pair.
# A prefixed literal (``b"x"``) keeps the span's raw first byte (the
# prefix) instead of the opening quote unless the edge computation is
# delimiter-aware; the surviving lone closing quote then pairs with a
# LATER literal's opener in every downstream naive string-skip and
# swallows real code — ranged ``lexical_dead`` / fabricated module
# aborts over live functions (the false-suppression direction).
# ---------------------------------------------------------------------------


def _assert_delimiters_balanced(view: str) -> None:
    for q in ('"', "'", "`"):
        assert view.count(q) % 2 == 0, (
            f"unbalanced {q!r} in blanked view: {view!r}"
        )
    for op, cl in (("{", "}"), ("[", "]"), ("(", ")")):
        assert view.count(op) == view.count(cl), (
            f"unbalanced {op}{cl} in blanked view: {view!r}"
        )


@pytest.mark.parametrize(("language", "src"), [
    # Rust prefixed / raw / byte literals — span starts at the prefix.
    ("rust", 'let a = b"x";'),
    ("rust", 'let a = r"y";'),
    ("rust", "let a = b'z';"),
    ("rust", 'let a = br"w";'),
    ("rust", 'let a = r#"if false { raw"#;'),
    ("rust", "let a = b'\"';"),
    # PHP prefixed binary strings (both quote kinds, both cases).
    ("php", "<?php\n$a = b'x';\n"),
    ("php", '<?php\n$a = B"x";\n'),
    # Ruby: prefix-delimited symbols, char literals, %-arrays (brace
    # AND bracket delimited — the closer is a BRACKET, so a surviving
    # edge would desync brace counting, not quote skipping).
    ("ruby", 'x = :"sym"'),
    ("ruby", 'x = ?"'),
    ("ruby", "x = %w{a b}"),
    ("ruby", "x = %i[a b]"),
    ("ruby", "x = %q(a)"),
    # JS family: regex with flags (last byte is a flag char, and the
    # pattern carries a quote), tagged templates.
    ("javascript", 'let r = /a"b/gi;'),
    ("javascript", 'let t = tag`a ${"x"} b`;'),
    ("typescript", 'let r = /a"b/gi;'),
    ("tsx", 'let r = /a"b/gi;'),
])
def test_edges_mode_survivors_balance(language, src):
    _requires(language)
    out = blank_noncode(language, src)
    assert out is not None
    assert len(out) == len(src)  # ASCII fixtures: byte-stable
    _assert_delimiters_balanced(out)
    # Literal content never survives.
    for leaked in ("if false", "raw", "sym"):
        if leaked in src:
            assert leaked not in out


@pytest.mark.parametrize(("language", "src", "expected"), [
    # The opening quote survives IN PLACE of the prefix — the token
    # stays in value position and the pair balances.
    ("rust", 'let a = b"x";', 'let a =  " ";'),
    ("rust", "let a = b'z';", "let a =  ' ';"),
    ("php", "<?php $a = b'x';", "<?php $a =  ' ';"),
    ("ruby", 'x = :"sym"', 'x =  "   "'),
    # No balanced pair exists → the whole span blanks (never a lone
    # delimiter).
    ("ruby", 'x = ?"', "x =   "),
    ("ruby", "x = %w{a b}", "x =        "),
])
def test_prefixed_literal_keeps_matching_opening_delimiter(
        language, src, expected):
    _requires(language)
    assert blank_noncode(language, src) == expected


def test_non_ascii_content_preserves_line_structure():
    _requires("javascript")
    src = 'let s = "héllo — ünïcode";\nif (false) { dead(); }\n'
    out = blank_noncode("javascript", src)
    assert out is not None
    assert out.count("\n") == src.count("\n")
    assert "if (false) { dead(); }" in out
    assert "héllo" not in out
