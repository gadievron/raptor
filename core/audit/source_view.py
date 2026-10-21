"""Sanitized source views — comments, strings, and dead regions blanked.

Lexical checkers that regex raw source treat prose as code: a comment
that merely MENTIONS a sink ("/* do not use memcpy here */") satisfies
a presence check, and a comment mentioning a declaration ("/* legacy:
void check_perm() removed */") forges an absence/shape receipt.  Both
directions are hostile-repo steerable, so every lexical receipt must
be earned against a view with comments and string/char literals
blanked out.

:func:`sanitized_view` is the shared chokepoint: single-pass scanner,
newlines preserved (line numbers stay valid), blanked spans replaced
with spaces.  Language is chosen from the file extension; unknown
extensions get the C-family scanner (its comment/string forms are the
common denominator for C/C++/Java/Go/Rust/JS/TS).  Per-language
string grammar rides on top of that common denominator: C/C++ raw
strings (``R"delim(…)delim"``), Rust raw strings (``r#"…"#``), Java
text blocks (triple-quote delimited), Go raw backticks, JS/TS template literals
(``${…}`` interpolation stays visible — it is executable code, and
blanking it forged absence receipts), PHP ``#`` comments,
multi-line ``'…'``/``"…"``/backtick strings, heredoc/nowdoc bodies,
``#[…]`` attributes (code) and ``?>`` (closes a one-line comment and,
in code state only, leaves PHP mode — inline HTML up to the next
``<?php``/``<?=`` is output data: blanked like a string, never lexed),
Kotlin/Swift triple-quote multi-line strings, NESTING block comments
for Kotlin/Swift/Rust, C# verbatim strings (``@"…"`` — ``""``
doubling, no backslash escapes) and raw string literals, and Lua
``--``/``--[[…]]`` comments with ``[[…]]`` long strings.  All the
multi-line forms carry state across lines, so a comment marker
inside string data can never open or close comment state (the
swallow direction), and an escaped quote can never close a literal
early.  Documented residuals for the newer C-family members, all
known-direction: Kotlin ``${…}`` / Swift ``\\(…)`` / C# ``$"{…}"``
string interpolation blanks as data (an interpolated call is hidden
from blanked-view consumers — same class as the perl variable-
interpolation residual), Swift extended delimiters (``#"…"#``) and
C# raw strings fenced with more than three quotes take the plain
string/text-block paths.  PHP residual: a source whose leading
inline text is NOT markup (plain text before the first ``<?``) starts
in PHP mode — snippets carry no open tag — so an apostrophe there
opens string state; the parity fallback below bounds it to that line
and reports ``php-unterminated-string``, but code on that line after
the apostrophe (``it's <?php exec($c); ?>``) can still be blanked.  Perl quote-like operators (``q qq qw qx m qr s tr y``) and
heredocs are unmodeled: their text stays visible as code, and a ``#``
inside one (``qr/#/``) reads as a comment and blanks the rest of the
line — perl guards must not decide on this view.

Ambiguity — the canonical form.  The view has two kinds of consumer
with OPPOSITE fail-safe directions: detectors (a sink must never be
hidden — ambiguous text should be SHOWN) and suppressors (a guard that
switches a detector off — mis-lexed text must never suppress).  So
when the lexer meets a construct whose reading it has to guess, it
(a) prefers SHOWING code in the view where it can — most ambiguous
regions are left verbatim (never blanked, never lexed, so they cannot
flip lexer state past themselves) — and (b) reports the guess through
:func:`sanitized_view_with_status`, which returns
``SanitizedView(text, ambiguous, reasons)``: ``text`` is exactly
:func:`sanitized_view`'s output for the same arguments (whose
signature and ``str`` return are unchanged), ``ambiguous`` is
``bool(reasons)``, and ``reasons`` is a sorted tuple of stable codes.
``ambiguous=True`` means the view may be wrong in EITHER direction:
text that is not code may be shown, and code may be blanked.
Suppressors must fail open (not suppress) when ``ambiguous``.
Detectors that need certainty must consult it too: a guess that
renders one reading can still blank code that the other reading has
— a JS ``/`` read as division after an unmatched ``)``
(``js-regex-after-paren``) or past a regex length bound
(``js-regex-or-division``; a regex body longer than the bound is lexed
as code and a quote in it can open a string), and the PHP single-line
fallback (``php-unterminated-string``, e.g. plain text with an
apostrophe before the first ``<?``). A detector that must never lose
a sink should re-check the raw text when ``ambiguous`` is True.  No
in-repo caller uses :func:`sanitized_view_with_status` yet: the
existing callers (including the prefilter suppressor views) call
:func:`sanitized_view` and never see ``ambiguous``.  Codes:

- ``php-hash-bracket`` — ``#[…]`` that does not parse as a PHP 8
  attribute group (it may span lines; a comment opener or ``?>`` inside
  it disqualifies it), or whose next token (whitespace and comments
  skipped) is not one an attribute can precede in its context: in a
  function/fn/closure parameter list a parameter; after ``new`` only
  ``class``; in a class-like body a member (modifiers, ``var``,
  ``const``, ``function``, ``case``); inside a function body or block a
  function/closure/arrow fn/class-like (``static`` only before
  ``function``/``fn``); at the top level of the input also a full
  method or property declaration, since callers pass methods cut out
  of their class. PHP 7 reads ``#[`` as a comment and a statement after
  it is valid only in that reading: the line, up to ``?>``, is shown
  verbatim.
- ``php-short-open-tag`` — a bare ``<?`` in inline HTML (opens PHP only
  with short_open_tag On; ``<?xml``): shown verbatim to the next ``?>``
  or ``<?php``/``<?=``.
- ``php-script-tag`` — ``<script language="php">`` (PHP 5 only):
  shown verbatim to ``</script>``.
- ``php-leading-bom`` — a leading UTF-8 BOM (skipped for the
  leading-state check).
- ``php-leading-markup`` — the source starts (after BOM/whitespace)
  with markup (``<`` + letter, ``!``, ``/``): whole template or
  markup-shaped fragment is a guess, so the leading HTML run is shown
  verbatim up to the first unambiguous open tag (to end of input when
  there is none).  ``<=``/``< $x``/``<<<`` starts are code.
- ``php-heredoc-closer`` — a heredoc closer only PHP >= 7.3 accepts
  (indented, or followed by anything but an optional ``;`` and the
  newline): both readings are scanned (closer taken / body continues
  to the next closer PHP < 7.3 accepts) and every character either
  reading shows is kept, so neither reading can hide the other's
  code. Every such flexible closer marks the
  input ambiguous (suppressors fail open on modern heredoc style —
  the safe direction, kept deliberately). Closers follow PHP's label
  rule — every non-ASCII character continues a label, so ``Té`` never
  closes ``<<<T``.
- ``php-unterminated-string`` / ``php-unterminated-heredoc`` — a PHP
  multi-line literal ran off the end of the input: some quote was
  mis-read and string parity is untrusted, so the scan is redone with
  single-line strings, unterminated heredocs scanned as code, and
  inline HTML shown (damage bounded per line, code shown).
- ``js-regex-after-paren`` — JS/TS ``/`` right after a ``)`` whose
  ``(`` the forward scan never saw (the input starts mid-expression):
  regex vs division depends on whether that ``)`` closed an
  ``if``/``while``/``for``/``with`` head, so division is kept and the
  guess reported. A ``)`` the scan matched is resolved exactly:
  control head (``if``/``while``/``for``/``with``, ``for await``,
  comments allowed before the ``(``; not a member/private name such as
  ``Symbol.for(``/``this.#if(``) → regex, anything else → division.
  A keyword glued to a longer identifier by an invisible or combining
  character (``a\u200dif(``) is undecided too and reported here.
- ``js-regex-or-division`` — JS/TS ``/`` after ``++``/``--`` or after a
  regex literal separated by a newline or comment: the view does not
  try to resolve these; it renders the slash as division (code shown)
  and reports the guess. A regex literal whose body does not close
  within ``_JS_REGEX_MAX_LEN`` (32768) characters on its line is not
  followed either (division, reported); once an earlier candidate on
  the same line failed to close, the bound for the rest of that line
  is ``_JS_REGEX_RETRY_LEN`` (2000) — together they keep a line of
  repeated ``(/[`` openers linear. Remaining JS regex-vs-division
  heuristics are a documented residual of this regex-grade scanner.
- ``unterminated-block-comment``, ``-text-block``,
  ``-verbatim-string``, ``-raw-string`` (C++/Rust raw, Go backtick),
  ``-template-literal``, ``-triple-string``, ``-doc-block`` (perl POD,
  ruby ``=begin``), ``-long-bracket`` (lua) — a multi-line construct
  ran off the end of the input (blanking behaviour unchanged, except
  that an unterminated hash-language triple-quoted string now blanks
  through end of input; base left its last three characters visible).
  Single-line literals stop at their newline and are not reported;
  the python f-string and ruby/shell interpolation walks and the
  ``#if 0`` pass do not report.

JS/TS whitespace follows ECMAScript in every JS decision: WhiteSpace
(TAB VT FF SP NBSP ZWNBSP and Unicode Zs) and LineTerminator (LF CR LS
PS — which also end a ``//`` comment and a regex literal) are never
identifier characters (PHP keeps ASCII whitespace; NBSP is a PHP label
byte). A keyword spelled as a property or private name (``.in``,
``?.typeof``, ``.#for``) is an identifier. Template literals nested
``_JS_TEMPLATE_MAX_DEPTH`` (200) or more levels deep inside ``${…}``
are not followed (the remainder is shown,
``unterminated-template-literal``).
Decided residual: JSX is not modelled — a closing tag's ``/`` (``</p>``)
is read as a regex opener and can blank an expression container up to
the next ``/`` on the line (``</p>{exec(cmd)}<br/>``), silently; JSX
needs its own grammar (out of scope for this scanner).

``keep_strings=True`` selects the comments-only view: string
literals stay verbatim while comments still blank.  Consumers whose
refusal logic must SEE string prose (the prefilter's trivial-wrapper
judged view — over-inclusion there only costs a review) read this
mode; the preprocessor-dead blanking is skipped in it because that
detection is only sound over a fully-blanked view (kept string data
spelling ``#if 0`` would otherwise mint a fake dead region — the
swallow direction).

Division of responsibility: this module is the shared REGEX-GRADE
single-pass scanner for in-flight textual views over sources and
segments (checker receipts, prefilter views) — no parser
dependencies, tolerant of snippets.  Node-fidelity blanking of whole
inventory files (grammar-table-driven, tree-sitter-backed) lives in
:mod:`core.inventory.lexical_view`; new consumers pick one of the
two, never a bespoke stripper.

The C-family scanner also blanks the two preprocessor-dead channels
with the same one-planted-line attacker capability as a comment:
``#if 0 … #endif`` regions (whole-condition constant-zero spellings
only — ``0``/``(0)``/``0x0``/``0L``/``00`` are dead in every build;
any macro-bearing condition, including a zero prefix like
``#if 0 || FOO``, is build-dependent and not judged here — that
residual is documented, not covered) and, for C/C++ (and unmapped
extensions, which default to C) only, backslash-line-continued ``//``
comments (splicing happens before comment recognition, so the
continued line is comment text to the compiler; no other C-family
language splices).
"""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_left
from dataclasses import dataclass
from typing import Callable, NamedTuple

# Extensions handled by the hash-comment (Python/shell-style) scanner.
_HASH_COMMENT_EXTS = (
    ".py", ".pyi", ".sh", ".bash", ".rb", ".pl", ".tcl",
    ".yaml", ".yml", ".toml",
)

# Language-id routing for callers that already know the language
# (checkers holding an inventory language id or a tree-sitter grammar
# name rather than a file path).
_HASH_COMMENT_LANGS = frozenset({
    "python", "ruby", "shell", "bash", "perl", "yaml", "toml",
})

_LUA_EXTS = (".lua",)

# Extension → language id for the hash-comment scanner's per-language
# interpolation grammar (see _strip_python_like). Extensions not named
# here keep the interpolation-free common denominator.
_HASH_COMMENT_EXT_LANG = {
    ".py": "python", ".pyi": "python",
    ".sh": "shell", ".bash": "bash",
    ".rb": "ruby", ".pl": "perl",
    ".toml": "toml", ".yaml": "yaml", ".yml": "yaml",
}


@dataclass(frozen=True)
class _CFamilySpec:
    """Per-language string grammar riding on the C-family scanner.

    ``backtick``: ``"none"`` (a backtick is code), ``"raw"`` (Go raw
    string — multi-line, no escapes), or ``"template"`` (JS/TS
    template literal — multi-line, escapes, ``${…}`` interpolation
    scanned as code).  ``single_quote_strings``: JS/TS treat
    ``'...'`` as a full string literal; everywhere else in the C
    family a single quote only ever opens a short char/rune literal —
    treating it as a to-end-of-line string made a Rust lifetime tick
    (``&'a str``) blank the rest of the line, forging absence
    receipts (PHP ``'...'`` IS a full string — see the php spec).
    ``php_tags``: PHP's open/close-tag and attribute grammar —
    ``?>`` closes a one-line comment and, in CODE state only, leaves
    PHP mode until the next unambiguous open tag (inline HTML between
    is output data, blanked like a string literal); ``#[`` opens a PHP
    8 attribute when its bracket parses as one. The ambiguous forms
    (see the module docstring) are left verbatim and reported.
    ``multiline_strings``: quoted strings ('…', "…", PHP backtick)
    span lines; an unterminated one triggers the single-line fallback
    rescan in :func:`_strip_c_family`.
    ``line_splicing``: backslash-newline continues a ``//`` comment
    onto the next line — C preprocessor translation phase 2, so only
    the C/C++ specs (and the unmapped-extension default) set it; in
    every other language the newline ends the comment and splicing
    there blanked the next live line.  The
    remaining flags switch on the language's own multi-line/raw
    string forms and PHP's extra comment/heredoc grammar.
    """

    backtick: str = "none"
    single_quote_strings: bool = False
    hash_line_comments: bool = False
    cpp_raw_strings: bool = False
    rust_raw_strings: bool = False
    java_text_blocks: bool = False
    text_block_escapes: bool = True
    nested_block_comments: bool = False
    csharp_verbatim_strings: bool = False
    php_heredocs: bool = False
    php_interpolation: bool = False
    php_tags: bool = False
    multiline_strings: bool = False
    regex_literals: bool = False
    line_splicing: bool = False


# Unmapped extensions/language ids are mostly C-preprocessed files
# the extension table does not name (.inc/.ipp/.inl/.tcc/.cu/.m), so
# the default keeps the C preprocessor's line splicing.
_DEFAULT_C_SPEC = _CFamilySpec(line_splicing=True)
_JS_SPEC = _CFamilySpec(
    backtick="template", single_quote_strings=True, regex_literals=True)

_C_FAMILY_SPECS = {
    # C headers are shared with C++ and C11 has no competing meaning
    # for the raw-string opener shape, so C gets the C++ raw grammar
    # too (a false raw-open needs the exact `R"delim(` spelling).
    "c": _CFamilySpec(cpp_raw_strings=True, line_splicing=True),
    "cpp": _CFamilySpec(cpp_raw_strings=True, line_splicing=True),
    # Rust block comments NEST (the Rust reference) — closing at the
    # first `*/` left interior comment prose visible as code.
    "rust": _CFamilySpec(rust_raw_strings=True, nested_block_comments=True),
    "java": _CFamilySpec(java_text_blocks=True),
    "go": _CFamilySpec(backtick="raw"),
    "javascript": _JS_SPEC,
    "typescript": _JS_SPEC,
    "jsx": _JS_SPEC,
    "tsx": _JS_SPEC,
    # PHP: `'...'` is a full string literal (only `\'`/`\\` escape;
    # the default escape model matches) — read as a char-literal
    # candidate, `'/*'` was skipped and its marker opened a phantom
    # block comment that blanked live code (the swallow direction).
    # All three PHP quote forms ('…', "…", `…`) span lines: a
    # single-line stop re-opened string state on a literal's closing
    # line and read a `?>` on a continuation line as a close tag.
    # Inline HTML is owned by the tag state, so a markup apostrophe
    # never opens a string.
    "php": _CFamilySpec(
        single_quote_strings=True, hash_line_comments=True,
        php_heredocs=True, php_interpolation=True, php_tags=True,
        multiline_strings=True,
    ),
    # Kotlin: `"""` raw strings are multi-line with NO escape
    # processing (a backslash is data — honouring escapes let a
    # trailing `\"""` push the close past the real terminator, the
    # swallow direction), and block comments NEST per the language
    # spec (closing at the first `*/` left interior comment prose
    # visible as code — the over-inclusion direction).
    "kotlin": _CFamilySpec(
        java_text_blocks=True, text_block_escapes=False,
        nested_block_comments=True,
    ),
    # Swift: multi-line string literals are `"""` delimited WITH
    # escape processing (the Java model), and block comments nest.
    "swift": _CFamilySpec(
        java_text_blocks=True, nested_block_comments=True,
    ),
    # C#: `"""` raw string literals have no escape processing, and
    # verbatim strings (`@"…"`, `$@"…"`/`@$"…"`) are multi-line, use
    # `""` doubling for a literal quote, and give the backslash NO
    # escape meaning — the default escape model read `@"dir\"` as an
    # escaped quote and desynced string state from there (the swallow
    # direction). Block comments do not nest.
    "csharp": _CFamilySpec(
        java_text_blocks=True, text_block_escapes=False,
        csharp_verbatim_strings=True,
    ),
}

_C_FAMILY_EXT_LANG = {
    ".c": "c", ".h": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".rs": "rust", ".java": "java", ".go": "go",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".php": "php", ".phtml": "php",
    ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift",
    ".cs": "csharp",
}


# Char-literal shape: 'x' or a short escape ('\n', '\'', '\x41').
_CHAR_LIT_RE = re.compile(r"'(?:\\[^\n]{1,3}|[^'\\\n])'")


class SanitizedView(NamedTuple):
    """Result of :func:`sanitized_view_with_status`.

    ``text`` is exactly what :func:`sanitized_view` returns for the same
    arguments. ``ambiguous`` is ``bool(reasons)``; ``reasons`` is the
    sorted tuple of stable reason codes (see the module docstring)."""

    text: str
    ambiguous: bool
    reasons: tuple[str, ...]


def sanitized_view_with_status(
    source: str, file_path: str = "", *, language: str | None = None,
    keep_strings: bool = False,
) -> SanitizedView:
    """:func:`sanitized_view` plus the lexer's ambiguity report.

    Same arguments, same ``text``. ``ambiguous`` is True when the scan
    met a construct whose reading the lexer had to guess (or that ran
    off the end of the input); the view then prefers SHOWING code where
    it can, but may be wrong in either direction (see the module
    docstring for the codes that can still blank code). Suppressor-
    style consumers (a guard that switches a detector OFF when it sees
    text) must fail open — not suppress — when ``ambiguous`` is True;
    detector-style consumers that must never lose a sink should
    re-check the raw text then. No in-repo caller uses this function
    yet; the existing callers use :func:`sanitized_view`.
    """
    reasons: set[str] = set()
    text = _build_view(source, file_path, language, keep_strings, reasons)
    return SanitizedView(text, bool(reasons), tuple(sorted(reasons)))


def sanitized_view(
    source: str, file_path: str = "", *, language: str | None = None,
    keep_strings: bool = False,
) -> str:
    """Return *source* with comments and string literals blanked.

    Every blanked character becomes a space; newlines inside blanked
    regions are preserved, so offsets and line numbers computed on the
    view map 1:1 onto the original text.

    The scanner is chosen from *language* (an inventory language id
    such as ``"python"``/``"java"``/``"go"``) when given, else from
    the *file_path* extension. Segments work too: the input does not
    have to be a whole file, so a checker can sanitize just the
    handler/clause text it is about to regex.

    ``keep_strings=True`` blanks comments only, leaving string
    literals verbatim (see the module docstring for the direction
    contract and why preprocessor-dead blanking is skipped in that
    mode). :func:`sanitized_view_with_status` returns the same text
    plus the ambiguity report.
    """
    return _build_view(source, file_path, language, keep_strings, None)


def _build_view(
    source: str, file_path: str, language: str | None,
    keep_strings: bool, reasons: set[str] | None,
) -> str:
    if not source:
        return source
    if language:
        lang = language.lower()
        if lang == "lua":
            return _strip_lua(
                source, keep_strings=keep_strings, reasons=reasons)
        if lang in _HASH_COMMENT_LANGS:
            return _strip_python_like(
                source, keep_strings=keep_strings, lang=lang,
                reasons=reasons)
        spec = _C_FAMILY_SPECS.get(lang, _DEFAULT_C_SPEC)
    else:
        lower = (file_path or "").lower()
        if lower.endswith(_LUA_EXTS):
            return _strip_lua(
                source, keep_strings=keep_strings, reasons=reasons)
        if lower.endswith(_HASH_COMMENT_EXTS):
            ext = "." + lower.rsplit(".", 1)[-1]
            return _strip_python_like(
                source, keep_strings=keep_strings,
                lang=_HASH_COMMENT_EXT_LANG.get(ext), reasons=reasons)
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        spec = _C_FAMILY_SPECS.get(
            _C_FAMILY_EXT_LANG.get(ext, ""), _DEFAULT_C_SPEC)
    view = _strip_c_family(
        source, spec, keep_strings=keep_strings, reasons=reasons)
    if keep_strings or spec.php_tags:
        # PHP has no preprocessor: a `#if 0` line can only be comment
        # text or inline HTML, never a directive — and ambiguous inline
        # regions are left VERBATIM, so judging such a line as a dead
        # region would blank live code in a later `<?php` block (the
        # swallow direction).
        return view
    return _blank_if0_regions(view)


# Preprocessor-dead region detection. Runs on the comment/string-
# blanked view, so a ``#if 0`` inside a comment or string is already
# spaces and never triggers.
#
# Always-dead conditions are matched CONSTANT-ONLY with the whole
# condition anchored: every zero spelling (``0``, ``(0)``, ``0x0``,
# ``0L``, ``00``, ``0u``, nested parens) is unconditionally dead in
# every build, while any macro-bearing condition — including a zero
# PREFIX like ``#if 0 || FOO``, which is LIVE when FOO is truthy —
# is refused (build-dependent truth is not judged here).
_PP_IF_COND_RE = re.compile(r"^[ \t]*#[ \t]*if\b(?P<cond>.*)$")
_PP_ALWAYS_DEAD_COND_RE = re.compile(
    r"[ \t(]*0+(?:[xX]0+)?[uUlL]*[ \t)]*"
)
_PP_IF_RE = re.compile(r"^[ \t]*#[ \t]*(?:if|ifdef|ifndef)\b")
_PP_ENDIF_RE = re.compile(r"^[ \t]*#[ \t]*endif\b")
_PP_ELSE_RE = re.compile(r"^[ \t]*#[ \t]*(?:else|elif)\b")


def _is_always_dead_if(ln: str) -> bool:
    """True for an ``#if`` whose whole condition is a constant zero
    (any spelling) — dead in every build. Trailing comment text is
    already spaces on the blanked view this runs over; a trailing
    ``\r`` (CRLF input) is tolerated."""
    m = _PP_IF_COND_RE.match(ln)
    if m is None:
        return False
    cond = m.group("cond").rstrip("\r")
    return _PP_ALWAYS_DEAD_COND_RE.fullmatch(cond) is not None


def _blank_if0_regions(view: str) -> str:
    """Blank always-dead ``#if`` regions from a comment/string-blanked
    view.

    Preprocessor-dead text is prose to the compiler exactly like a
    comment — a planted ``#if 0`` block steers lexical receipts with
    the same one-line attacker capability. Dead runs from the
    directive to its matching ``#endif``, or to a matching
    ``#else``/``#elif`` (those arms may be live); nested conditionals
    inside the dead region are tracked by depth. Conservative on
    purpose: only whole-condition constant-zero spellings are judged
    (see ``_PP_ALWAYS_DEAD_COND_RE``) — any macro-bearing condition
    is build-dependent and left visible; an unterminated region
    blanks to end of input (dead until proven otherwise — refusal
    direction for receipt consumers). Line lengths are preserved, so
    offsets keep mapping 1:1.
    """
    lines = view.split("\n")  # line-model: view text derives from \n-model audit reads; lengths kept 1:1
    out: list[str] = []
    depth = 0
    for ln in lines:
        if depth == 0:
            if _is_always_dead_if(ln):
                depth = 1
                out.append(" " * len(ln))
            else:
                out.append(ln)
            continue
        if _PP_IF_RE.match(ln):
            depth += 1
        elif _PP_ENDIF_RE.match(ln):
            depth -= 1
        elif depth == 1 and _PP_ELSE_RE.match(ln):
            depth = 0
        out.append(" " * len(ln))
    return "\n".join(out)


def _blank(chars: list[str], start: int, end: int) -> None:
    """Blank ``chars[start:end]``, keeping newlines."""
    for i in range(start, end):
        if chars[i] != "\n":
            chars[i] = " "


def _strip_c_family(
    source: str, spec: _CFamilySpec, *, keep_strings: bool = False,
    reasons: set[str] | None = None,
) -> str:
    """C-family scan with the PHP fallback contract: when a multi-line
    quoted string (or heredoc) runs off the end of the input, some
    quote was mis-read and string parity is flipped for everything
    after it — the scan is redone with single-line strings and inline
    HTML left verbatim (damage bounded per line, code shown), and the
    ambiguity is reported."""
    found: set[str] = set()

    def run(pre73: bool) -> str:
        v = _scan_c_family(source, spec, keep_strings, found, False, pre73)
        if spec.multiline_strings and found & _PHP_PARITY_REASONS:
            v = _scan_c_family(source, spec, keep_strings, found, True, pre73)
        return v

    view = run(False)
    if "php-heredoc-closer" in found:
        # A heredoc closer only PHP >= 7.3 accepts: scan the PHP < 7.3
        # reading too (that closer is body text there) and keep every
        # character either reading shows — the view never hides what
        # one of the two readings has as code.
        other = run(True)
        view = "".join(
            a if a != " " else b for a, b in zip(view, other))
    if reasons is not None:
        reasons |= found
    return view


#: Reasons that mean PHP string parity cannot be trusted (an
#: unterminated multi-line literal reached end of input).
_PHP_PARITY_REASONS = frozenset({
    "php-unterminated-string", "php-unterminated-heredoc"})


def _scan_c_family(
    source: str, spec: _CFamilySpec, keep_strings: bool,
    found: set[str], fallback: bool, pre73: bool = False,
) -> str:
    chars = list(source)
    n = len(source)
    flag = found.add

    def blank_str(start: int, end: int) -> None:
        """Blank STRING content — a no-op on the comments-only view."""
        if not keep_strings:
            _blank(chars, start, end)

    def verbatim(start: int, end: int) -> None:
        """Ambiguous region: shown as-is in both views, never lexed."""

    # Inline HTML after a code-state `?>` is unambiguous output data
    # (blanked) — except in the fallback rescan, where state is
    # uncertain and everything is shown.
    html_render = verbatim if fallback else blank_str
    multiline = spec.multiline_strings and not fallback

    terminators = _HeredocTerminators(source) if spec.php_heredocs else None
    # `#[` arm state: the last accepted attribute (end, context) so a
    # chain `#[A] #[B] $x` inherits the parameter context.
    last_attr: tuple[int, str] = (-1, "stmt")
    # JS paren tracking for the regex-vs-division call after `)`: a
    # stack of "is this `(` a control-statement head", and the most
    # recent `)` as (position, kind).
    js_parens: list[bool | None] = []
    js_last_close: tuple[int, str | None] = (-1, None)
    js_last_regex_end = -1
    # [line end of the last failed regex candidate]: later candidates
    # on that line use the short retry bound.
    js_rx_state = [-1]
    # PHP bracket stack for the `#[` context: "decl(" (a function/fn/
    # closure parameter list), "(", "[", "class{" (a class-like body)
    # or "{".
    php_brackets: list[str] = []
    i = 0
    if spec.php_tags:
        i = _php_leading_state(source, flag, verbatim)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            if spec.regex_literals:
                # JS/TS: any LineTerminator (CR, LS, PS too) ends it —
                # one search (an extra LF-only scan first was O(rest of
                # input) per comment on LF-free text).
                lt = _JS_LT_RE.search(source, i)
                end = -1 if lt is None else lt.start()
            else:
                end = source.find("\n", i)
            # Backslash-newline splicing happens BEFORE comment
            # recognition in C/C++ (translation phase 2): a
            # ``// … \`` comment continues onto the next physical
            # line, which is comment text to the compiler — a guard
            # "hidden" there must blank like any other comment byte.
            # No other C-family language splices (Java/JS/Go/Rust/
            # C#/Kotlin/Swift/PHP end the comment at the newline), and
            # splicing there blanked the next LIVE line.
            while spec.line_splicing and end > 0 and (
                source[end - 1] == "\\"
                or (source[end - 1] == "\r" and end > 1
                    and source[end - 2] == "\\")
            ):
                end = source.find("\n", end + 1)
            end = n if end < 0 else end
            if spec.php_tags:
                end = _php_line_comment_end(source, i, end)
            _blank(chars, i, end)
            i = end
        elif spec.php_tags and ch == "?" and nxt == ">":
            # `?>` in CODE state (every string/comment/heredoc arm
            # consumes its own `?>` first) leaves PHP mode: the text up
            # to the next open tag is inline HTML — output data, NOT
            # lexed (an apostrophe or `//` in markup is not a string or
            # comment opener). The tag itself stays visible.
            i = _php_inline_html(source, i + 2, html_render, verbatim, flag)
        elif ch == "/" and nxt == "*":
            if spec.nested_block_comments:
                end = _nested_block_comment_end(
                    source, i,
                    on_eof=lambda: flag("unterminated-block-comment"))
            else:
                close = source.find("*/", i + 2)
                if close < 0:
                    flag("unterminated-block-comment")
                end = n if close < 0 else close + 2
            _blank(chars, i, end)
            i = end
        elif (spec.regex_literals and ch == "/"
                and (rex_end := _js_regex_end(
                    source, i, flag, js_last_close,
                    js_last_regex_end, chars, js_rx_state)) is not None):
            # JS/TS regex literal. Lexed BEFORE it can mint comment
            # state: `/\//` (the escaped-slash regex) read in code
            # position as division-then-`//` blanked real code after
            # the regex out of BOTH views — the swallow direction.
            # The comment arms above still win at `//`/`/*` (a regex
            # cannot start with `/` or `*`), and _js_regex_end judges
            # the division-vs-regex ambiguity from the preceding
            # token (after `)`: the forward-tracked paren kind),
            # falling back to division (scan on) when the candidate
            # does not close on its own line.
            blank_str(i + 1, rex_end - 1)
            # Flags belong to the literal: the value ends after them.
            i = js_last_regex_end = _js_regex_flags_end(source, rex_end)
        elif spec.php_tags and ch == "#" and nxt == "[":
            # PHP 8 attribute `#[…]` is code; in PHP 7 the same text is
            # a `#` comment. Unambiguous only when the bracket parses as
            # an attribute group (it may span lines — under PHP 7 the
            # continuation lines of a multi-line `#[X(` would be a
            # syntax error) AND the next token is one
            # an attribute can precede in this context (a declaration
            # start — member modifiers only in a class-like body; in a
            # declaration's parameter list also a parameter; after
            # `new`, only `class`). Otherwise the reading is a guess:
            # the line (to `?>`, where both readings leave PHP) is
            # shown verbatim — never lexed, so a prose apostrophe can't
            # open string state — and reported.
            ctx = _php_attr_context(chars, i, last_attr, php_brackets)
            # Scan bound: the span cap, and the next `#[` — consecutive
            # attribute scans never overlap, so the arm stays linear (a
            # `#[` inside an argument string just ends the scan early:
            # reported as ambiguous, the safe side).
            bound = min(n, i + _PHP_ATTR_SPAN_CAP)
            nxt_attr = source.find("#[", i + 2, bound)
            close = _php_attribute_close(
                source, i, bound if nxt_attr < 0 else nxt_attr)
            if close is not None and _php_attr_follow_ok(
                    source, close, ctx, min(n, close + _PHP_ATTR_SPAN_CAP)):
                last_attr = (close, ctx)
                i += 1
            else:
                flag("php-hash-bracket")
                end = source.find("\n", i)
                end = _php_line_comment_end(
                    source, i, n if end < 0 else end)
                i = end
        elif spec.hash_line_comments and ch == "#":
            end = source.find("\n", i)
            end = n if end < 0 else end
            if spec.php_tags:
                end = _php_line_comment_end(source, i, end)
            _blank(chars, i, end)
            i = end
        elif (spec.php_heredocs and ch == "<"
                and source.startswith("<<<", i)):
            nxt_i = _php_heredoc(
                source, chars, i, blank_str,
                keep_strings=keep_strings,
                interpolation=spec.php_interpolation,
                on_eof=lambda: flag("php-unterminated-heredoc"),
                trust_unterminated=not fallback,
                terminators=terminators,
                on_uncertain=lambda: flag("php-heredoc-closer"),
                pre73=pre73,
            )
            i = nxt_i if nxt_i is not None else i + 3
        elif (spec.csharp_verbatim_strings and ch == '"'
                and _csharp_verbatim_prefix(source, i)):
            # @"…" / $@"…" / @$"…" — multi-line, `""` doubling, no
            # backslash escapes (see the csharp spec comment).
            # Judged BEFORE the triple-quote arm: `@"""x"` is a
            # verbatim string whose content begins with a doubled
            # quote, not a raw-string opener.
            end = _csharp_verbatim_end(
                source, i,
                on_eof=lambda: flag("unterminated-verbatim-string"))
            blank_str(i + 1, max(i + 1, end - 1))
            i = end
        elif (spec.java_text_blocks and ch == '"'
                and source.startswith('"""', i)):
            end = _java_text_block_end(
                source, i, escapes=spec.text_block_escapes,
                on_eof=lambda: flag("unterminated-text-block"))
            blank_str(i + 3, max(i + 3, end - 3))
            i = end
        elif (spec.cpp_raw_strings and ch == '"'
                and (delim := _cpp_raw_delim(source, i)) is not None):
            # R"delim( … )delim" — content is raw across lines; an
            # interior quote or comment marker is data, never a close.
            closer = ')' + delim + '"'
            body = i + 1 + len(delim) + 1
            close = source.find(closer, body)
            if close < 0:
                flag("unterminated-raw-string")
            end = n if close < 0 else close + len(closer)
            blank_str(body, n if close < 0 else close)
            i = end
        elif (spec.rust_raw_strings and ch == '"'
                and (hashes := _rust_raw_hashes(source, i)) is not None):
            closer = '"' + "#" * hashes
            close = source.find(closer, i + 1)
            if close < 0:
                flag("unterminated-raw-string")
            end = n if close < 0 else close + len(closer)
            blank_str(i + 1, n if close < 0 else close)
            i = end
        elif ch == "'" and not spec.single_quote_strings:
            # Char/rune literal only, and only when it has the
            # char-literal shape (closing quote within a couple of
            # characters, escapes allowed). A lone tick — a Rust
            # lifetime, an apostrophe in code — is NOT a literal and
            # must not swallow the rest of the line.
            lit_end = _char_literal_end(source, i)
            if lit_end is None:
                i += 1
            else:
                blank_str(i + 1, lit_end - 1)
                i = lit_end
        elif ch == "`" and spec.backtick == "template":
            i = _template_literal(
                source, chars, i, blank_str,
                on_eof=lambda: flag("unterminated-template-literal"),
                flag=flag, rx_state=js_rx_state)
        elif spec.php_interpolation and ch in ('"', "`"):
            # PHP double-quoted and backtick (shell-exec) strings
            # span lines and execute complex-syntax
            # interpolation — `{$obj->method($arg)}` CALLS the method
            # — so those expressions stay visible as code (the
            # template-arm direction contract). Simple `$ident` /
            # `${name}` interpolation stays data: a bare variable
            # mention cannot spell a call, same posture as the perl
            # variable-interpolation residual.
            i = _php_dq_end(
                chars, source, i, keep_strings=keep_strings,
                multiline=multiline,
                on_eof=lambda: flag("php-unterminated-string"))
        elif ch == '"' or ch == "'" or (
                ch == "`" and spec.backtick == "raw"):
            if ch == "`":
                eof = lambda: flag("unterminated-raw-string")  # noqa: E731
            elif multiline:
                eof = lambda: flag("php-unterminated-string")  # noqa: E731
            else:
                # Single-line literals stop at the newline — they can
                # never carry state past their own line; not reported.
                eof = None
            end = _string_end(source, i, ch, raw=(ch == "`"),
                              multiline=multiline, on_eof=eof)
            # Keep the delimiters so shapes like ``""`` stay visible;
            # blank only the contents. (_string_end never returns
            # past n, so the bound is simply end - 1.)
            blank_str(i + 1, end - 1)
            i = end
        elif spec.regex_literals and ch == "(":
            js_parens.append(_js_control_paren(chars, i))
            i += 1
        elif spec.regex_literals and ch == ")":
            if js_parens:
                head = js_parens.pop()
                js_last_close = (
                    i, None if head is None
                    else "control" if head else "expr")
            else:
                js_last_close = (i, None)
            i += 1
        elif spec.php_tags and ch in "([{":
            if ch == "(":
                php_brackets.append(
                    "decl(" if _php_decl_paren(chars, i) else "(")
            elif ch == "[":
                php_brackets.append("[")
            else:
                php_brackets.append(
                    "class{" if _php_class_brace(chars, i) else "{")
            i += 1
        elif spec.php_tags and ch in ")]}":
            if php_brackets and php_brackets[-1][-1] == {
                    ")": "(", "]": "[", "}": "{"}[ch]:
                php_brackets.pop()
            i += 1
        else:
            i += 1
    return "".join(chars)


# Perl POD: any line-start ``=word`` opens documentation until the
# ``=cut`` line (perl's own lexer rule — no column-0 statement begins
# with ``=`` followed by a letter). Ruby: column-0 ``=begin`` opens a
# block comment until the column-0 ``=end`` line. Both read as CODE
# before this — comment prose minted call-shaped false positives in
# counting consumers (the over-inclusion direction), and neither was
# in the declared residual list.
_PERL_POD_OPEN_RE = re.compile(r"=[A-Za-z]\w*")
_PERL_POD_CUT_RE = re.compile(r"^=cut\b[^\n]*", re.MULTILINE)
_RUBY_BEGIN_RE = re.compile(r"=begin(?![0-9A-Za-z_])")
_RUBY_END_RE = re.compile(r"^=end\b[^\n]*", re.MULTILINE)


def _line_block_comment_end(
    source: str, open_pos: int, close_re: re.Pattern[str],
    on_eof: Callable[[], None] | None = None,
) -> int:
    """Index just past the line closing the block comment opened at
    ``open_pos`` (terminator searched from the opener line's end so a
    self-terminating opener like perl's bare ``=cut`` still scans
    forward), or end of input when unterminated — both languages read
    an unterminated block as comment-to-EOF."""
    line_end = source.find("\n", open_pos)
    m = None if line_end < 0 else close_re.search(source, line_end + 1)
    if m is None:
        if on_eof is not None:
            on_eof()
        return len(source)
    return m.end()


def _strip_python_like(
    source: str, *, keep_strings: bool = False, lang: str | None = None,
    reasons: set[str] | None = None,
) -> str:
    chars = list(source)
    n = len(source)

    def flag(reason: str) -> None:
        if reasons is not None:
            reasons.add(reason)

    def doc_eof() -> None:
        flag("unterminated-doc-block")
    i = 0
    while i < n:
        ch = source[i]
        if ch == "=" and (i == 0 or source[i - 1] == "\n"):
            if lang == "perl" and _PERL_POD_OPEN_RE.match(source, i):
                if _PERL_POD_CUT_RE.match(source, i):
                    # A bare ``=cut`` opens and closes in one line —
                    # blanking to the NEXT =cut would swallow live
                    # code after it.
                    line_end = source.find("\n", i)
                    end = n if line_end < 0 else line_end
                else:
                    end = _line_block_comment_end(
                        source, i, _PERL_POD_CUT_RE, on_eof=doc_eof)
                _blank(chars, i, end)
                i = end
                continue
            if lang == "ruby" and _RUBY_BEGIN_RE.match(source, i):
                end = _line_block_comment_end(
                    source, i, _RUBY_END_RE, on_eof=doc_eof)
                _blank(chars, i, end)
                i = end
                continue
            i += 1
        elif ch == "#":
            if i > 0 and source[i - 1] == "$":
                # Perl `$#array` (last index) / shell `$#` (arg
                # count): a sigil-prefixed `#` is code, not a comment
                # opener — blanking from it swallowed sink-as-argument
                # references out of the wrapper's reference view (the
                # suppression direction).
                i += 1
                continue
            end = source.find("\n", i)
            end = n if end < 0 else end
            _blank(chars, i, end)
            i = end
        elif ch in ('"', "'"):
            interp = _interp_kind(source, i, ch, lang)
            if interp == "fstring":
                # Full f-string grammar walk — needed even under
                # keep_strings, because only the walk finds the TRUE
                # closing quote once PEP 701 lets the outer quote
                # char reappear inside {…} expressions.
                i = _python_fstring_end(
                    chars, source, i, keep_strings=keep_strings)
                continue
            if interp in ("ruby", "shell"):
                # Interpolation-aware walk in BOTH view modes: only
                # the walk finds the TRUE closing quote once a kept
                # expression contains a nested double-quoted string
                # (`"#{ f("#{a}") }"` — pairing the outer quote with
                # the nested opener resumed the scan inside the
                # interpolation, where `#{` read as a comment and
                # blanked live code after the string to end of line).
                # Same recursion contract as _python_fstring_end.
                i = _interp_string_end(
                    chars, source, i, interp, keep_strings=keep_strings)
                continue
            triple = source[i:i + 3] in ('"""', "'''")
            if triple:
                # The language's escape model applies: an escaped
                # quote inside a python triple string is data, not the
                # closer (closing there blanked live code after the
                # real closer); TOML ''' literals have none. An
                # unterminated triple blanks to end of input — all of
                # it (the old `end - 3` bound leaked the last three
                # characters).
                if _quote_escapes(source, i, ch, lang):
                    close = _py_triple_close(source, i, ch)
                else:
                    close = source.find(source[i:i + 3], i + 3)
                    close = n if close < 0 else close
                if close >= n:
                    flag("unterminated-triple-string")
                if not keep_strings:
                    _blank(chars, i + 3, close)
                i = min(close + 3, n)
            else:
                # Shell single-quoted strings have NO escapes: `'\''`
                # ends at the second quote. Treating `\'` as an escape
                # desynced quote state and blanked live code after the
                # real closer to end of line (the swallow direction).
                # EXCEPT $'…' (ANSI-C quoting), where escapes DO
                # apply — ending that form at `\'` inverted the same
                # desync.
                end = _string_end(
                    source, i, ch,
                    escapes=_quote_escapes(source, i, ch, lang),
                    doubling=(lang == "yaml" and ch == "'"))
                if not keep_strings:
                    _blank(chars, i + 1, end - 1)
                i = end
        else:
            i += 1
    return "".join(chars)


def _quote_escapes(
    source: str, i: int, quote: str, lang: str | None,
) -> bool:
    """Whether backslash escapes apply inside the plain string literal
    opened at ``i`` — per-language quote grammar, single-homed so the
    top-level scan and the nested-string arm of the interpolation
    walk can never disagree (they did: the nested arm applied the
    default escape model to shell single quotes, swallowing live
    code)."""
    if lang in ("shell", "bash") and quote == "'":
        # POSIX single quotes have no escapes; $'…' is ANSI-C quoting
        # where they DO apply.
        return i > 0 and source[i - 1] == "$"
    if lang in ("toml", "yaml") and quote == "'":
        # TOML literal strings and YAML single-quoted scalars have no
        # backslash escapes — treating \' as one desynced quote state
        # and swallowed the rest of the line after the true closer
        # (YAML spells a literal quote by doubling instead — see
        # ``doubling`` in :func:`_string_end`).
        return False
    return True


def _interp_kind(
    source: str, i: int, quote: str, lang: str | None,
) -> str | None:
    """The interpolation grammar active inside the string opened at
    ``i``, or None for a plain literal.

    Interpolation expressions are executable code — the same direction
    contract as the JS/TS template arm ("interpolation stays visible —
    it is executable code, and blanking it forged absence receipts").
    Blanking `f"{os.popen(cmd)}"` / `"#{system(cmd)}"` / `"$(rm $x)"`
    hid the sink from every blanked-view consumer while the language
    executes it. Modeled: python f-strings, ruby ``#{…}`` (double
    quotes), shell ``$(…)``/``${…}``/backticks (double quotes).
    Documented residuals: perl string interpolation (variable-only
    without the ``@{[…]}`` block idiom, whose grammar is the unmodeled
    perl quote-construct class), ruby ``%``-literals, heredocs, and
    plain multi-line double-quoted strings (single-line stop — a
    continuation line reads as a comment), and shell heredocs. All
    pinned known-direction. Python f-strings get the full nesting
    grammar (:func:`_python_fstring_end`): same-quote nested literals
    (PEP 701) and nested f-strings inside ``{…}`` at any compile-
    reachable depth, multi-line replacement fields in every quote
    form, conversion tags, and format specs.
    """
    if lang == "python":
        prefix = _py_string_prefix(source, i)
        if prefix is None:
            return None
        return "fstring" if "f" in prefix.lower() else None
    if lang == "ruby" and quote == '"':
        return "ruby"
    if lang in ("shell", "bash") and quote == '"':
        return "shell"
    return None


#: Nesting bound for the ruby/shell interpolation walk — same
#: degradation contract as ``_PY_FSTRING_MAX_DEPTH``: past the cap
#: the walk stops and the remainder stays visible (over-inclusion,
#: never a swallow). Real code nests a handful of levels; only a
#: planted `"#{"`*N bomb approaches the cap.
_INTERP_MAX_DEPTH = 50


def _interp_string_end(
    chars: list[str], source: str, i: int, kind: str, *,
    keep_strings: bool, depth: int = 0,
) -> int:
    """Consume the ruby/shell double-quoted string opened at ``i``,
    blanking literal text while interpolation EXPRESSIONS stay
    visible as code (under ``keep_strings`` nothing blanks, but the
    walk still lexes the full grammar — only the walk finds the true
    closing quote once a kept expression contains a nested
    double-quoted string).

    Ruby ``#{…}`` and shell ``$(…)``/``${…}``/backticks are modeled;
    nested double-quoted strings inside a kept expression recurse
    with the same grammar (their literal text blanks as data, their
    own interpolations stay visible — mirroring
    :func:`_python_fstring_end`). LITERAL text stops at a newline
    (the plain multi-line double-quote residual is unchanged); a
    kept expression may span lines (it is code either way). Returns
    the index just past the closing quote.
    """
    n = len(source)
    if depth >= _INTERP_MAX_DEPTH:
        return n
    j = i + 1

    def blank1(k: int) -> None:
        if not keep_strings and chars[k] != "\n":
            chars[k] = " "

    while j < n:
        ch = source[j]
        if ch == "\\":
            # Pair-blank: ruby and shell escapes genuinely suppress
            # interpolation ("\#{…}", "\$(", "\`" are literal data
            # in the running language).
            blank1(j)
            if j + 1 < n:
                blank1(j + 1)
            j += 2
            continue
        if kind == "ruby" and source.startswith("#{", j):
            # The `#` sigil blanks (a line-leading `#` in the view
            # would read as a comment/directive to textual line
            # filters); the braced expression stays visible.
            blank1(j)
            j = _interp_expr(
                chars, source, j + 2, kind, "{", "}",
                keep_strings=keep_strings, depth=depth)
            continue
        if kind == "shell":
            if source.startswith("$(", j):
                j = _interp_expr(
                    chars, source, j + 2, kind, "(", ")",
                    keep_strings=keep_strings, depth=depth)
                continue
            if source.startswith("${", j):
                j = _interp_expr(
                    chars, source, j + 2, kind, "{", "}",
                    keep_strings=keep_strings, depth=depth)
                continue
            if ch == "`":
                # Backtick command substitution runs inside double
                # quotes — code, same class as $( ).
                k = j + 1
                while k < n and source[k] != "`":
                    k += 2 if source[k] == "\\" else 1
                j = min(k + 1, n)
                continue
        if ch == '"':
            return j + 1
        if ch == "\n":
            return j + 1
        blank1(j)
        j += 1
    return n


def _interp_expr(
    chars: list[str], source: str, j: int, kind: str,
    opener: str, closer: str, *, keep_strings: bool, depth: int = 0,
) -> int:
    """Scan the interpolation expression whose opener precedes ``j``,
    keeping it visible as code while nested string literals get their
    own treatment: double-quoted strings recurse into
    :func:`_interp_string_end` (data again, own fields visible),
    single-quoted literals blank their contents under the language's
    escape model (:func:`_quote_escapes` — shell single quotes have
    none). Returns the index just past the matching closer;
    unterminated expressions — including nesting past
    ``_INTERP_MAX_DEPTH`` — keep the remainder visible
    (over-inclusion, never a swallow).
    """
    n = len(source)
    if depth >= _INTERP_MAX_DEPTH:
        return n
    depth += 1
    lang = "shell" if kind == "shell" else "ruby"
    level = 1
    while j < n and level:
        c = source[j]
        if c == opener:
            level += 1
            j += 1
        elif c == closer:
            level -= 1
            j += 1
        elif c == '"':
            j = _interp_string_end(
                chars, source, j, kind,
                keep_strings=keep_strings, depth=depth)
        elif c == "'":
            e = _string_end(
                source, j, c,
                escapes=_quote_escapes(source, j, c, lang))
            for k in range(j + 1, min(e, n) - 1):
                if not keep_strings and chars[k] != "\n":
                    chars[k] = " "
            j = e
        else:
            j += 1
    return j


def _py_string_prefix(source: str, i: int) -> str | None:
    """The string-prefix letters immediately before the quote at
    ``i`` (``f``/``r``/``b``/``u`` combinations, at most two), or
    None when those letters are the tail of a longer identifier
    (``shelf"…"`` — not a prefix)."""
    j = i - 1
    prefix = ""
    while j >= 0 and source[j] in "fFrRbBuU" and len(prefix) < 2:
        prefix += source[j]
        j -= 1
    if j >= 0 and (source[j].isalnum() or source[j] == "_"):
        return None
    return prefix


#: Nesting bound for the f-string walk (levels of nested f-string /
#: format-spec recursion). CPython itself refuses deeper nesting at
#: compile time (measured: 149 nested f-strings, 2 spec levels), so
#: no compile-valid source ever reaches the cap; only non-compiling
#: input (a planted `f"{`*N bomb) can, and it degrades to the
#: unterminated-field direction — remainder visible, never blanked.
#: Raising the cap costs stack frames (~2 per level against the
#: interpreter recursion limit); lowering it toward CPython's 149
#: leaves no headroom for future CPython limits.
_PY_FSTRING_MAX_DEPTH = 200


def _python_fstring_end(
    chars: list[str], source: str, i: int, *, keep_strings: bool,
    depth: int = 0,
) -> int:
    """Consume the python f-string opened at the quote at ``i``,
    blanking literal text while replacement-field expressions stay
    visible as code (under ``keep_strings`` nothing blanks, but the
    walk still lexes the full grammar — only the walk finds the true
    closing quote once nested literals may reuse the outer quote).

    Models the PEP 701 (3.12+) grammar: a ``{…}`` field may contain
    string literals of ANY quote — including the outer quote — and
    nested f-strings, recursed up to ``_PY_FSTRING_MAX_DEPTH``
    (deeper nesting cannot compile; past the cap the walk stops and
    the remainder stays visible — the over-inclusion direction).
    Returns the index just past the closing quote; LITERAL text in a
    single-quoted form stops at a newline (only replacement fields
    may span lines), an unterminated triple runs to end of input.
    """
    n = len(source)
    if depth >= _PY_FSTRING_MAX_DEPTH:
        return n
    q = source[i]
    triple = source.startswith(q * 3, i)
    raw = "r" in (_py_string_prefix(source, i) or "").lower()
    j = i + (3 if triple else 1)

    def blank1(k: int) -> None:
        if not keep_strings and chars[k] != "\n":
            chars[k] = " "

    while j < n:
        ch = source[j]
        if ch == "\\":
            if not raw and source.startswith("\\N{", j):
                # Named-character escape: these braces are escape
                # syntax, not a replacement field — the whole unit
                # is string DATA. Raw f-strings disable the escape
                # (rf"\N{x}" DOES interpolate x), so raw skips this
                # arm and the brace is judged below.
                close = source.find("}", j + 3)
                nl = source.find("\n", j + 3)
                if close != -1 and (nl == -1 or close < nl):
                    for k in range(j, close + 1):
                        blank1(k)
                    j = close + 1
                    continue
            if j + 1 < n and source[j + 1] in "{}":
                # There is no brace escape in f-strings: the
                # backslash is string DATA and the brace stays live
                # (CPython f'\{1+1}' == '\2'). Blank the backslash
                # alone so the brace is judged by the brace arms —
                # consuming the pair swallowed a whole executable
                # interpolation as string data.
                blank1(j)
                j += 1
                continue
            blank1(j)
            if j + 1 < n:
                blank1(j + 1)
            j += 2
            continue
        if source.startswith("{{", j) or source.startswith("}}", j):
            # Doubled braces are literal brace DATA, not a field.
            blank1(j)
            blank1(j + 1)
            j += 2
            continue
        if ch == "{":
            j = _python_field(
                chars, source, j + 1,
                keep_strings=keep_strings, depth=depth)
            continue
        if triple:
            if source.startswith(q * 3, j):
                return j + 3
        else:
            if ch == q or ch == "\n":
                return j + 1
        blank1(j)
        j += 1
    return n


def _python_field(
    chars: list[str], source: str, j: int, *,
    keep_strings: bool, depth: int = 0,
) -> int:
    """Scan the f-string replacement field whose ``{`` precedes ``j``,
    keeping the expression visible as code. What executes, per
    CPython: the expression (visible), nested string literals' own
    fields if f-prefixed (recursed — their literal text blanks as
    data), and the format spec's nested ``{…}`` fields (visible);
    what is data: nested plain-literal contents and the format
    spec's literal text (both blank). A ``:`` at bracket depth 0
    always starts the format spec (even ``{x:=…}`` — CPython reads
    the spec, not a walrus). Conversion tags (``!r``/``!s``/``!a``)
    and the ``=`` self-documenting marker are field syntax, left
    visible as code. ``#`` comments (legal in 3.12+ multi-line
    fields) blank to end of line in both view modes. A field may
    span lines in EVERY quote form (PEP 701 allows it in
    single-quoted f-strings too — stopping at the newline made the
    true closing quote re-open string state and blank live code
    after it). Returns the index just past the closing ``}``;
    unterminated fields — including nesting past
    ``_PY_FSTRING_MAX_DEPTH``, which cannot compile — keep the
    remainder visible (over-inclusion, never a swallow).
    """
    n = len(source)
    if depth >= _PY_FSTRING_MAX_DEPTH:
        return n
    depth += 1
    bracket = 0
    in_spec = False
    while j < n:
        ch = source[j]
        if ch == "\n":
            j += 1
            continue
        if in_spec:
            if ch == "{":
                j = _python_field(
                    chars, source, j + 1,
                    keep_strings=keep_strings, depth=depth)
                continue
            if ch == "}":
                return j + 1
            if not keep_strings:
                chars[j] = " "
            j += 1
            continue
        if ch in "([{":
            bracket += 1
            j += 1
            continue
        if ch in ")]}":
            if ch == "}" and bracket == 0:
                return j + 1
            bracket = max(0, bracket - 1)
            j += 1
            continue
        if ch == ":" and bracket == 0:
            in_spec = True
            j += 1
            continue
        if ch == "#":
            # Comment inside a multi-line field — comment prose
            # blanks in BOTH view modes, like any other comment.
            end = source.find("\n", j)
            end = n if end < 0 else end
            _blank(chars, j, end)
            j = end
            continue
        if ch in ('"', "'"):
            prefix = _py_string_prefix(source, j)
            if prefix and "f" in prefix.lower():
                j = _python_fstring_end(
                    chars, source, j, keep_strings=keep_strings,
                    depth=depth)
                continue
            if source.startswith(ch * 3, j):
                close = _py_triple_close(source, j, ch)
                if not keep_strings:
                    _blank(chars, j + 3, close)
                j = min(close + 3, n)
                continue
            e = _string_end(source, j, ch)
            if not keep_strings:
                _blank(chars, j + 1, min(e, n) - 1 if e <= n else n)
            j = e
            continue
        j += 1
    return n


def _py_triple_close(source: str, j: int, quote: str) -> int:
    """Index of the ``quote*3`` closing the triple-quoted literal
    opened at ``j`` (escapes honoured), or end of input when
    unterminated."""
    n = len(source)
    closer = quote * 3
    k = j + 3
    while k < n:
        if source[k] == "\\":
            k += 2
            continue
        if source.startswith(closer, k):
            return k
        k += 1
    return n


def _char_literal_end(source: str, start: int) -> int | None:
    """Index just past a char-literal's closing quote, or None.

    Accepts the char-literal shape only: one plain character
    (``'x'``) or a short escape (``'\\n'``, ``'\\x41'`` — at most
    three characters after the backslash). Anything else is not a
    literal.
    """
    m = _CHAR_LIT_RE.match(source, start)
    return m.end() if m else None


def _string_end(
    source: str, start: int, quote: str, *,
    raw: bool = False, escapes: bool = True, doubling: bool = False,
    multiline: bool = False, on_eof: Callable[[], None] | None = None,
) -> int:
    """Index just past the closing quote (or end of line/file).

    Unterminated single-line strings stop at the newline — a lone
    apostrophe in text must not swallow the rest of the file.
    ``escapes=False`` disables backslash handling for grammars whose
    literal form has none (shell/TOML/YAML single quotes) while
    keeping the newline stop; ``doubling`` treats a doubled quote as
    a literal quote (YAML single-quote grammar). ``multiline`` drops
    the newline stop for grammars whose quoted strings span lines
    (PHP) — unterminated then runs to end of input. ``on_eof`` is
    called when the literal runs off the end of the input unclosed.
    """
    n = len(source)
    i = start + 1
    while i < n:
        ch = source[i]
        if ch == "\\" and not raw and escapes:
            i += 2
            continue
        if ch == quote:
            if doubling and i + 1 < n and source[i + 1] == quote:
                i += 2
                continue
            return i + 1
        if ch == "\n" and not raw and not multiline:
            return i + 1
        i += 1
    if on_eof is not None:
        on_eof()
    return n


def _strip_lua(
    source: str, *, keep_strings: bool = False,
    reasons: set[str] | None = None,
) -> str:
    """Lua scanner: ``--``/``--[[…]]`` comments, ``[[…]]``/``[=[…]=]``
    long strings (multi-line, no escapes), and quote strings.  ``//``
    is Lua 5.3 integer division and ``/*`` is not a comment — routing
    Lua through the C-family scanner blanked live code after those
    operators (the swallow direction)."""
    chars = list(source)
    n = len(source)
    i = 0
    while i < n:
        ch = source[i]
        if ch == "-" and source.startswith("--", i):
            m = _LUA_LONG_OPEN_RE.match(source, i + 2)
            if m:
                closer = "]" + m.group(1) + "]"
                close = source.find(closer, m.end())
                if close < 0 and reasons is not None:
                    reasons.add("unterminated-long-bracket")
                end = n if close < 0 else close + len(closer)
            else:
                end = source.find("\n", i)
                end = n if end < 0 else end
            _blank(chars, i, end)
            i = end
        elif ch == "[" and (m := _LUA_LONG_OPEN_RE.match(source, i)):
            closer = "]" + m.group(1) + "]"
            close = source.find(closer, m.end())
            if close < 0 and reasons is not None:
                reasons.add("unterminated-long-bracket")
            end = n if close < 0 else close + len(closer)
            if not keep_strings:
                _blank(chars, m.end(), n if close < 0 else close)
            i = end
        elif ch in ('"', "'"):
            end = _string_end(source, i, ch)
            if not keep_strings:
                _blank(chars, i + 1, end - 1)
            i = end
        else:
            i += 1
    return "".join(chars)


_LUA_LONG_OPEN_RE = re.compile(r"\[(=*)\[")

# Tags met in inline HTML. `<?php` (followed by whitespace or end of
# input) and `<?=` always open PHP. A bare `<?` opens PHP only when
# short_open_tag is On (php.ini-production ships it Off; `<?xml` is
# the classic victim), and `<script language="php">` only on PHP 5 —
# both are ambiguous.
_PHP_HTML_TAG_RE = re.compile(
    r"<\?(?:php(?=\s|$)|=)"
    r"|<script\s+language\s*=\s*[\"']?php[\"']?\s*>"
    r"|<\?",
    re.IGNORECASE,
)
_PHP_OPEN_TAG_RE = re.compile(r"<\?(?:php(?=\s|$)|=)", re.IGNORECASE)
_PHP_SCRIPT_CLOSE_RE = re.compile(r"</script\s*>", re.IGNORECASE)


def _php_inline_html(
    source: str, start: int, render, verbatim, flag,
) -> int:
    """Consume inline HTML from ``start``; return where PHP code
    resumes (an unambiguous open tag) or end of input.

    Plain markup goes through ``render`` (blank for output data after
    a code-state ``?>``; verbatim when the HTML state itself is a
    guess). Ambiguous tags are shown VERBATIM and reported: a bare
    ``<?`` (``php-short-open-tag``) up to the next ``?>`` — where both
    readings are back in HTML — or the next unambiguous open tag; a
    ``<script language="php">`` (``php-script-tag``) up to its
    ``</script>``."""
    n = len(source)
    j = start
    # Next unambiguous open tag, searched once and reused while it is
    # still ahead (positions only grow) — re-searching per bare `<?`
    # made a `<? a ?>` run quadratic.
    reopen: re.Match[str] | None = None
    reopen_from = -1
    while True:
        m = _PHP_HTML_TAG_RE.search(source, j)
        if m is None:
            render(j, n)
            return n
        render(j, m.start())
        tag = m.group(0)
        if tag != "<?" and not tag.lower().startswith("<script"):
            return m.start()  # `<?php` / `<?=`: code resumes here
        if tag.lower().startswith("<script"):
            flag("php-script-tag")
            close = _PHP_SCRIPT_CLOSE_RE.search(source, m.end())
            end = n if close is None else close.end()
            verbatim(m.start(), end)
            j = end
            continue
        # bare `<?`
        flag("php-short-open-tag")
        close = source.find("?>", m.end())
        if reopen_from < 0 or (reopen is not None
                               and reopen.start() < m.end()):
            reopen = _PHP_OPEN_TAG_RE.search(source, m.end())
            reopen_from = m.end()
        if reopen is not None and (close < 0 or reopen.start() < close):
            verbatim(m.start(), reopen.start())
            return reopen.start()
        end = n if close < 0 else close + 2
        verbatim(m.start(), end)
        if end >= n:
            return n
        j = end


def _php_leading_state(source: str, flag, verbatim) -> int:
    """Where the PHP scan starts. A source opening (after an optional
    BOM and whitespace) with markup — ``<`` followed by a letter,
    ``!``, ``/`` or ``?`` — is either a whole template (PHP starts it
    in HTML mode) or a fragment of markup-shaped data; the reading is
    a guess, so the leading HTML run is shown VERBATIM (never blanked,
    never lexed) and reported (``php-leading-markup``). A leading BOM
    is reported (``php-leading-bom``). Anything else — including
    ``<=``/``< $x`` continuation lines and a ``<<<`` heredoc opener —
    starts in code."""
    lead = 0
    if source.startswith("\ufeff"):
        flag("php-leading-bom")
        lead = 1
    while lead < len(source) and source[lead] in " \t\r\n\f\v":
        lead += 1
    if not (source.startswith("<", lead) and lead + 1 < len(source)
            and (source[lead + 1].isalpha() or source[lead + 1] in "!/?")):
        return 0
    if _PHP_OPEN_TAG_RE.match(source, lead):
        return lead
    if source[lead + 1] != "?":
        flag("php-leading-markup")
    return _php_inline_html(source, lead, verbatim, verbatim, flag)


# Attribute grammar for the `#[` arm: Name[(args)] {, Name[(args)]} [,]
# Whitespace (newlines included) may separate the tokens.
_PHP_ATTR_NAME_RE = re.compile(r"\s*\\?[A-Za-z_][\w\\]*\s*")
#: An attribute group must close within this many characters of its
#: `#[` (real ones are short); past it the reading is reported as
#: ambiguous. Bounds the per-`#[` scan, keeping the arm linear.
_PHP_ATTR_SPAN_CAP = 4096
# Declarations an attribute can precede in any context (PHP 8 grammar:
# functions, closures, arrow functions, classes and class members).
# An expression statement (`#[note] $x = guard($x);`) cannot follow an
# attribute — at statement level that line is only valid as a PHP 7
# comment.
# Declaration starts an attribute can precede, per context (PHP 8):
# statement level — functions, closures, arrow functions, class-likes
# (with their class modifiers), `static function`/`static fn`;
# class-like body — members (modifiers, `var`, `const`, `function`,
# enum `case`). An expression statement (`#[note] $x = guard($x);`,
# `static $v`, `static::f()`) cannot follow an attribute — that line is
# only valid as a PHP 7 comment.
_PHP_ATTR_STMT_DECL_RE = re.compile(
    r"(?:(?:abstract|final|readonly)\s+)*(?:class|interface|trait|enum)"
    r"(?![\w\\])"
    r"|(?:static\s+)?(?:function|fn)(?![\w\\])")
# At the top level of the input (no bracket open) a method or property
# declaration is accepted too: callers hand over method sources cut out
# of their class (`#[Route(...)]\npublic function dl(...)`). Only full
# method/property shapes (intersection/DNF types too), class constants
# (with a modifier or a type — a bare `const X` may be a global
# constant) and enum cases count — prose (`#[todo] public function
# names are camelCase`) does not.
_PHP_ATTR_TOP_MEMBER_RE = re.compile(
    r"(?:(?:public|private|protected|static|final|abstract|readonly|var)"
    r"\s+)+(?:function\s+&?[A-Za-z_]\w*\s*\("
    r"|const\s+(?:[?\w\\|&()]+\s+)?[A-Za-z_]\w*\s*="
    r"|(?:[?\w\\|&()]+\s+)?&?\$\w)"
    r"|const\s+[?\w\\|&()]+\s+[A-Za-z_]\w*\s*="
    r"|case\s+[A-Za-z_]\w*\s*[=;]")
_PHP_ATTR_MEMBER_DECL_RE = re.compile(
    r"(?:public|private|protected|static|final|abstract|readonly|var|"
    r"const|function|case)(?![\w\\])")
# Inside a declaration's parameter list: a parameter (`$x`, `&$x`,
# `...$x`, `?T $x`, `T|U $x`, `T &...$x`) or a promoted-property
# modifier.
_PHP_ATTR_PARAM_RE = re.compile(
    r"[$&?]|\.\.\.|(?:public|private|protected|readonly)(?![\w\\])"
    r"|[A-Za-z_\\][\w\\|]*[ \t]+&?(?:\.\.\.)?\$")
_PHP_NEW_RE = re.compile("new", re.IGNORECASE)
#: Test hook: when set to a dict or a Counter, the PHP class-header
#: scans add their step counts to it (missing keys start at 0). The
#: counts are derived from each scan's own loop bounds, so they pin the
#: scans' own linear work but cannot see work added elsewhere (a copy
#: per keyword, an output rebuild) — CPU-time scaling tests cover that.
#: None (no counting) in normal use.
_PHP_HEADER_STATS: dict[str, int] | None = None
_PHP_CLASS_HEADER_RE = re.compile(
    r"(?<![\w$:>\\])(?:class|interface|trait|enum)(?![\w$\\])")


def _ident_char(c: str, js: bool) -> bool:
    if c.isalnum() or c in "_$":
        return True
    return c > "\x7f" and not (js and _js_is_ws(c))


#: ECMAScript LineTerminator.
_JS_LINE_TERMINATORS = "\n\r\u2028\u2029"
_JS_LT_RE = re.compile("[\n\r\u2028\u2029]")
# A regex literal body after its opening `/`: escapes (a backslash takes
# the next character unless it is a line terminator — a regex literal
# never spans lines, escaped or not), `[...]` classes (where `/` is
# literal), anything else but a line terminator; the closing `/` ends
# it. The alternatives start with disjoint characters, so the match is
# linear; a C-speed match keeps a line of repeated `(/[` openers
# (each scanning to the end of the line) fast.
#: Longest regex literal body followed (characters) — above real
#: Unicode ID_Start/ID_Continue tables (7-8.5 KB in bundled code).
_JS_REGEX_MAX_LEN = 32768
#: The bound after a candidate on the same line already failed to
#: close: a hostile line of repeated `(/[` openers stays linear.
_JS_REGEX_RETRY_LEN = 2000
_JS_REGEX_BODY_RE = re.compile(
    "(?:\\\\[^\n\r\u2028\u2029]"
    "|\\[(?:\\\\[^\n\r\u2028\u2029]|[^\\]\\\\\n\r\u2028\u2029])*\\]"
    "|[^/\\\\\\[\n\r\u2028\u2029])*/")


def _js_is_ws(c: str) -> bool:
    """ECMAScript WhiteSpace or LineTerminator: TAB VT FF SP NBSP ZWNBSP,
    every Unicode Zs, and LF CR LS PS. JS-only — PHP whitespace is
    ASCII (NBSP is a PHP label byte)."""
    # NBSP (U+00A0) is in Zs; ZWNBSP (U+FEFF) is not, so it is listed.
    return (c in " \t\v\f\ufeff" or c in _JS_LINE_TERMINATORS
            or (c > "\x7f" and unicodedata.category(c) == "Zs"))


def _prev_sig(chars: list[str], j: int, *, js: bool = False) -> int:
    """Index of the last non-whitespace character at or before ``j`` in
    the view (comments are already blanked there), or -1. ``js``
    selects the ECMAScript whitespace set (:func:`_js_is_ws`);
    otherwise ASCII whitespace (PHP)."""
    if js:
        while j >= 0 and _js_is_ws(chars[j]):
            j -= 1
        return j
    while j >= 0 and chars[j] in " \t\r\n\f\v":
        j -= 1
    return j


def _word_ending_at(
    chars: list[str], e: int, *, js: bool = False,
) -> tuple[str, int]:
    """The identifier ending at ``e`` and its start: ``[A-Za-z0-9_$]``
    plus non-ASCII characters — every one for PHP (labels take every
    byte >= 0x80), every one except JS whitespace/line terminators for
    JS (ID_Continue takes ZWJ/ZWNJ, combining marks, U+00B7)."""
    w = e
    while w >= 0 and _ident_char(chars[w], js):
        w -= 1
    return "".join(chars[w + 1:e + 1]), w + 1


def _php_decl_paren(chars: list[str], i: int) -> bool:
    """True when the ``(`` at ``i`` opens a declaration's parameter
    list: ``function (``, ``fn (``, ``function name (`` (by-reference
    ``&`` allowed)."""
    j = _prev_sig(chars, i - 1)
    if j >= 0 and chars[j] == "&":
        j = _prev_sig(chars, j - 1)
    word, ws = _word_ending_at(chars, j)
    if word.lower() in ("function", "fn"):
        # `$o->fn(`, `X::function(`, `$o?->fn(` are calls.
        k = _prev_sig(chars, ws - 1)
        return not (k >= 1 and chars[k - 1:k + 1] in (["-", ">"], [":", ":"]))
    if not word or word[0] == "$":
        return False
    k = _prev_sig(chars, ws - 1)
    if k >= 0 and chars[k] == "&":
        k = _prev_sig(chars, k - 1)
    return _word_ending_at(chars, k)[0].lower() == "function"


def _php_class_brace(chars: list[str], i: int) -> bool:
    """True when the ``{`` at ``i`` opens a class-like body: the header
    since the previous ``;``/``{``/``}`` names ``class``/``interface``/
    ``trait``/``enum`` (not ``X::class``). The backward regions of
    successive braces are disjoint, and the header is copied and
    scanned a constant number of times, so the check is linear
    overall."""
    j = i - 1
    while j >= 0 and chars[j] not in ";{}":
        j -= 1
    # Quoted text is data even on the keep_strings view.
    header = _php_blank_quoted("".join(chars[j + 1:i]))
    n = len(header)
    ws_steps = 0
    new_ends = None
    found = False
    for m in _PHP_CLASS_HEADER_RE.finditer(header):
        # A keyword directly followed by `(` without `new` names a
        # function (`function enum(`, `public function trait(`) or is a
        # call (`if (enum($x))`) — only `new class(...)` opens a body.
        # Each keyword looks only at the whitespace on either side of
        # it (runs disjoint between keywords), never re-copies the
        # header.
        k = m.end()
        while k < n and header[k].isspace():
            k += 1
        ws_steps += k - m.end()
        if k < n and header[k] == "(":
            end = m.start()
            while end > 0 and header[end - 1].isspace():
                end -= 1
            ws_steps += m.start() - end
            if new_ends is None:
                new_ends = _PhpNewPrefixes(header)
            if not new_ends.ends_at(end):
                continue
        found = True
        break
    st = _PHP_HEADER_STATS
    if st is not None:
        st["header_chars"] = st.get("header_chars", 0) + i - 1 - j
        st["caller_ws"] = st.get("caller_ws", 0) + ws_steps
    return found


def _php_blank_quoted(text: str) -> str:
    """``text`` with every complete single- or double-quoted string
    (backslash escapes; an escape cannot take a newline) replaced by
    spaces of the same length — a linear hand scan equivalent to
    substituting ``'(?:\\\\.|[^'\\\\])*'|"(?:\\\\.|[^"\\\\])*"``, which re-scanned a
    run of escaped quotes from every quote (quadratic). A quote whose
    string does not close is left as is; the scan that found it open
    records where it died, and any later quote of the same kind before
    that point dies there too (it is the second character of a
    backslash pair of that scan, so a scan from it resumes on the same
    pair boundaries), so no run is scanned twice per quote kind."""
    out = list(text)
    n = len(text)
    dead = {"'": -1, '"': -1}
    steps = 0
    i = 0
    while i < n:
        c = text[i]
        if c not in dead or i < dead[c]:
            i += 1
            continue
        j = i + 1
        while j < n:
            d = text[j]
            if d == "\\":
                if j + 1 < n and text[j + 1] != "\n":
                    j += 2
                    continue
                break
            if d == c:
                break
            j += 1
        steps += j - i
        if j < n and text[j] == c:
            for k in range(i, j + 1):
                out[k] = " "
            i = j + 1
        else:
            dead[c] = j
            i += 1
    st = _PHP_HEADER_STATS
    if st is not None:
        st["quote_steps"] = st.get("quote_steps", 0) + steps
    return "".join(out)


class _PhpNewPrefixes:
    """Where, in one class header, the anonymous-class prefix can end:
    the word ``new`` followed by attribute groups and an optional
    ``readonly`` (whitespace between) — the shape before ``class(``.

    Precondition of :meth:`ends_at`: ``end`` is 0 or ``text[end - 1]``
    is not whitespace (``_php_class_brace`` trims before asking). Under
    it, ``ends_at(end)`` is True exactly when searching
    ``\\bnew(?:\\s*#\\[(?:[^\\[\\]]|\\[[^\\]]*\\])*\\])*(?:\\s+readonly)?$``
    (case-insensitive) in ``text[:end]`` would match. Without it the two
    differ: the regex's ``$`` also matches before a final LF, so for
    ``text = "new\\n"`` the search matches ``text[:4]`` while
    ``ends_at(4)`` is False (``ends_at(3)`` is True).

    That search re-scanned a run of attribute groups from every ``new``
    and for every keyword (quadratic). Here each attribute group is
    parsed once (a right-to-left table gives every position's group
    close), the chains of group ends reached from each ``new`` are
    followed once (they merge, and a visited end, marked in a bytearray,
    stops the walk), and each query only looks at its own ``end`` and
    the whitespace before a ``readonly`` tail — linear in the header
    plus the queries, worst case. Memory, transient per header of n
    characters: the ``close`` list (an 8-byte pointer per entry; the
    entries share int objects, one per ``]`` plus one for n, about 32
    bytes each on 64-bit CPython), the n + 1 byte endpoint bytearray
    and the header string itself (1-4 bytes per character) — at most
    about 45 bytes per header character, plus the ``list(text)`` copy
    (8 bytes per character) and its joined result in
    :func:`_php_blank_quoted`."""

    def __init__(self, text: str) -> None:
        n = len(text)
        self._text = text
        # close[r]: index of the `]` ending an attribute group whose
        # content resumes at r (a nested `[` skips to the next `]`), or
        # n when the group does not close. nxt: the nearest `]` right
        # of r.
        close = [n] * (n + 1)
        nxt = n
        for r in range(n - 1, -1, -1):
            c = text[r]
            if c == "]":
                nxt = r
                close[r] = r
            elif c == "[":
                close[r] = n if nxt >= n else close[nxt + 1]
            else:
                close[r] = close[r + 1]
        ends = bytearray(n + 1)
        expanded = 0
        ws_steps = 0
        for m in _PHP_NEW_RE.finditer(text):
            a = m.start()
            if a > 0 and (text[a - 1].isalnum() or text[a - 1] == "_"):
                continue
            p = a + 3
            while not ends[p]:
                ends[p] = 1
                expanded += 1
                q = p
                while q < n and text[q].isspace():
                    q += 1
                ws_steps += q - p
                if not (q + 1 < n and text[q] == "#" and text[q + 1] == "["):
                    break
                g = close[q + 2]
                if g >= n:
                    break
                p = g + 1
        self._ends = ends
        st = _PHP_HEADER_STATS
        if st is not None:
            st["prefix_steps"] = st.get("prefix_steps", 0) + n
            st["prefix_ends"] = st.get("prefix_ends", 0) + expanded
            st["prefix_ws"] = st.get("prefix_ws", 0) + ws_steps

    def ends_at(self, end: int) -> bool:
        """See the class docstring, including the precondition."""
        ends = self._ends
        if ends[end]:
            return True
        text = self._text
        s = end - 8
        if s < 1 or text[s:end].lower() != "readonly":
            return False
        k = s - 1
        found = False
        while k >= 0 and text[k].isspace():
            if ends[k]:
                found = True
                break
            k -= 1
        st = _PHP_HEADER_STATS
        if st is not None:
            st["query_ws"] = st.get("query_ws", 0) + s - k
        return found


def _php_new_class_prefix(text: str, end: int) -> bool:
    """One-off :meth:`_PhpNewPrefixes.ends_at` query (same
    precondition)."""
    return _PhpNewPrefixes(text).ends_at(end)


def _php_attr_context(
    chars: list[str], i: int, last_attr: tuple[int, str],
    brackets: list[str],
) -> str:
    """Syntactic context of the ``#[`` at ``i`` (read on the view, so
    comments are skipped): ``"param"`` after ``(``/``,`` directly inside
    a declaration's parameter list; the inherited context directly
    after an accepted attribute; ``"new"`` after the word ``new``;
    ``"member"`` directly inside a class-like body; ``"top"`` with no
    bracket open (the input may be a method cut out of its class); else
    ``"stmt"`` (inside a function body or other block)."""
    j = _prev_sig(chars, i - 1)
    top = brackets[-1] if brackets else ""
    if j < 0:
        # The input opens with the attribute (a method window cut out
        # of its class): top level.
        return "top"
    if chars[j] in "(,":
        return "param" if top == "decl(" else "stmt"
    if chars[j] == "]" and last_attr[0] == j + 1:
        return last_attr[1]
    word, ws = _word_ending_at(chars, j)
    if word.lower() == "new" and not (ws > 0 and chars[ws - 1] in "\\>:"):
        return "new"
    if top == "class{":
        return "member"
    return "top" if not brackets else "stmt"


def _php_attribute_close(source: str, i: int, line_end: int) -> int | None:
    """Index just past the ``]`` when the ``#[`` at ``i`` parses as a
    PHP 8 attribute group closing before ``line_end`` (the scan bound;
    the group may span lines), else None."""
    j = i + 2
    while True:
        m = _PHP_ATTR_NAME_RE.match(source, j, line_end)
        if m is None:
            return None
        j = m.end()
        if j < line_end and source[j] == "(":
            j = _php_balanced_end(source, j, line_end, attr=True)
            if j is None:
                return None
            while j < line_end and source[j] in " \t\r\n":
                j += 1
        if j < line_end and source[j] == ",":
            j += 1
            while j < line_end and source[j] in " \t\r\n":
                j += 1
            if j < line_end and source[j] == "]":
                return j + 1
            continue
        if j < line_end and source[j] == "]":
            return j + 1
        return None


def _php_attr_follow_ok(source: str, j: int, ctx: str, limit: int) -> bool:
    """True when the next token after an attribute group ending at
    ``j`` (whitespace, newlines and comments skipped, within ``limit``
    — an unclosed ``/*`` searched to end of input per attribute made a
    run of them quadratic) is one an attribute can precede in
    ``ctx``."""
    n = limit
    while j < n:
        c = source[j]
        if c in " \t\r\n":
            j += 1
        elif source.startswith("//", j) or (
                c == "#" and not source.startswith("#[", j)):
            # A one-line comment ends at the newline or at `?>` — the
            # close tag is then the next token (inline HTML cannot
            # follow an attribute).
            e = source.find("\n", j)
            j = _php_line_comment_end(source, j, len(source) if e < 0 else e)
        elif source.startswith("/*", j):
            e = source.find("*/", j + 2, n)
            if e < 0:
                return False
            j = e + 2
        else:
            break
    if j >= n:
        return False
    if source.startswith("#[", j):
        return True
    if ctx == "new":
        return re.match(r"class(?![\w\\])", source[j:j + 6]) is not None
    if ctx == "member":
        return _PHP_ATTR_MEMBER_DECL_RE.match(source, j) is not None
    if ctx == "param":
        return _PHP_ATTR_PARAM_RE.match(source, j) is not None
    if ctx == "top" and _PHP_ATTR_TOP_MEMBER_RE.match(source, j):
        return True
    return _PHP_ATTR_STMT_DECL_RE.match(source, j) is not None


def _php_balanced_end(
    source: str, j: int, end: int, *, attr: bool = False,
) -> int | None:
    """Index just past the bracket matching the opener at ``j``,
    quote-aware, within ``source[:end]``; None when it does not close
    there. With ``attr`` a comment opener (``/*``, ``//``, ``#``) or
    ``?>`` outside a string also answers None: PHP 7 reads the rest of
    the line as comment text and PHP 8 constant expressions hold no
    comment worth trusting here — either way not an unambiguous
    attribute."""
    depth = 0
    while j < end:
        c = source[j]
        if attr and (c == "#" or source.startswith(("/*", "//", "?>"), j)):
            return None
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return j + 1
        elif c in "'\"":
            k = j + 1
            while k < end and source[k] != c:
                k += 2 if source[k] == "\\" else 1
            if k >= end:
                return None
            j = k
        j += 1
    return None


def _php_line_comment_end(source: str, start: int, end: int) -> int:
    """End of the PHP one-line comment opened at ``start`` whose
    newline bound is ``end``: PHP closes a ``//``/``#`` comment at
    ``?>`` too (the tag itself is left for the code arm, which leaves
    PHP mode there). Block comments are unaffected — ``?>`` means
    nothing inside ``/* … */``."""
    tag = source.find("?>", start, end)
    return end if tag < 0 else tag


# PHP label characters: ASCII letters/digits/underscore and every byte
# 0x80-0xff (`[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*`). On decoded
# text every non-ASCII character is made of such bytes, so it continues
# a label too — `Té` is a longer label, never `T` followed by text.
_PHP_LABEL_CHARS = "0-9A-Za-z_\u0080-\U0010ffff"
_PHP_LABEL = rf"[A-Za-z_\u0080-\U0010ffff][{_PHP_LABEL_CHARS}]*"
# Heredoc opener: ``<<<ID`` / ``<<<"ID"`` (interpolating) /
# ``<<<'ID'`` (nowdoc), nothing but whitespace to end of line.
_PHP_HEREDOC_OPEN_RE = re.compile(
    rf"<<<[ \t]*(?:\"({_PHP_LABEL})\"|'({_PHP_LABEL})'|({_PHP_LABEL}))"
    r"[ \t]*\r?\n")


def _php_heredoc(
    source: str, chars: list[str], i: int, blank_str, *,
    keep_strings: bool = False, interpolation: bool = False,
    on_eof: Callable[[], None] | None = None,
    trust_unterminated: bool = True,
    terminators: _HeredocTerminators | None = None,
    on_uncertain: Callable[[], None] | None = None,
    pre73: bool = False,
) -> int | None:
    """Consume a PHP heredoc/nowdoc opened at ``i`` (``<<<``); blank
    its body up to the terminator line (PHP 7.3 flexible closers —
    the identifier may be indented and followed by punctuation).
    Heredoc bodies (``<<<ID`` / ``<<<"ID"``) execute complex-syntax
    interpolation exactly like double-quoted strings, so with
    *interpolation* their ``{$…}`` expressions stay visible
    (:func:`_php_complex_expr`); nowdoc bodies (``<<<'ID'``) never
    interpolate and blank whole. Returns the index just past the
    terminator identifier, or None when ``<<<`` does not open a
    heredoc here. An unterminated body calls ``on_eof``; with
    ``trust_unterminated=False`` (the fallback rescan) it is then not
    taken as a heredoc at all — the caller scans on as code. A closer
    only PHP >= 7.3 accepts (indented, or followed by anything but an
    optional ``;`` and the newline) calls ``on_uncertain``; it closes
    the heredoc unless ``pre73`` selects the PHP < 7.3 reading (body
    runs on to the next closer that reading accepts).
    :func:`_strip_c_family` scans both readings and keeps what either
    shows."""
    m = _PHP_HEREDOC_OPEN_RE.match(source, i)
    if m is None:
        return None
    ident = m.group(1) or m.group(2) or m.group(3)
    nowdoc = m.group(2) is not None
    if terminators is None:
        terminators = _HeredocTerminators(source)
    t = terminators.find(ident, m.end())
    if t is not None and not t[2]:
        if on_uncertain is not None:
            on_uncertain()
        if pre73:
            # The PHP < 7.3 reading: this closer is body text; the body
            # runs to the next closer that reading accepts (if none, it
            # is unterminated there — keep the 7.3 closer instead).
            t = terminators.find_certain(ident, t[1]) or t
    if t is None:
        if on_eof is not None:
            on_eof()
        if not trust_unterminated:
            return None
    body_end = len(source) if t is None else t[0]
    if interpolation and not nowdoc:
        _php_blank_interp_region(
            chars, source, m.end(), body_end, keep_strings=keep_strings)
    else:
        blank_str(m.end(), body_end)
    return len(source) if t is None else t[1]


class _HeredocTerminators:
    """Terminator-line lookup for one scan: the first line at or after
    ``start`` whose leading label run (after optional indentation) IS
    the identifier — PHP's rule: the closer must not be followed by a
    label character (``[a-zA-Z0-9_\\x80-\\xff]``), so the maximal run
    must equal it. A lazily built one-pass index (run -> sorted line
    starts) makes every lookup a bisect: re-searching to end of input
    per opener made a run of unterminated heredocs quadratic in the
    fallback rescan. ``find`` returns ``(line_start, label_end,
    pre_73_ok)``; ``pre_73_ok`` is False for a closer only PHP >= 7.3
    accepts (indented, or followed by more than an optional ``;``)."""

    _LINE_RE = re.compile(rf"^([ \t]*)([{_PHP_LABEL_CHARS}]+)", re.M)
    # PHP <= 7.2 closes only on LABEL, an optional `;`, then directly
    # the newline (no trailing blanks).
    _PRE73_TAIL_RE = re.compile(r";?\r?(?:\n|\Z)")

    def __init__(self, source: str) -> None:
        self._source = source
        self._index: dict[str, tuple[list[int], list[int], list[bool]]] | None = None
        self._certain: dict[str, list[tuple[int, int]]] = {}

    def _build(self) -> dict[str, tuple[list[int], list[int], list[bool]]]:
        index: dict[str, tuple[list[int], list[int], list[bool]]] = {}
        for m in self._LINE_RE.finditer(self._source):
            starts, ends, pre73 = index.setdefault(m.group(2), ([], [], []))
            starts.append(m.start())
            ends.append(m.end())
            ok = not m.group(1) and self._PRE73_TAIL_RE.match(
                self._source, m.end()) is not None
            pre73.append(ok)
            if ok:
                self._certain.setdefault(m.group(2), []).append(
                    (m.start(), m.end()))
        return index

    def find_certain(
        self, ident: str, start: int,
    ) -> tuple[int, int, bool] | None:
        """The first closer at or after ``start`` that PHP < 7.3 also
        accepts, as ``find`` returns it, or None."""
        if self._index is None:
            self._index = self._build()
        certain = self._certain.get(ident)
        if not certain:
            return None
        k = bisect_left(certain, (start, -1))
        if k == len(certain):
            return None
        return certain[k][0], certain[k][1], True

    def find(self, ident: str, start: int) -> tuple[int, int, bool] | None:
        if self._index is None:
            self._index = self._build()
        hit = self._index.get(ident)
        if hit is None:
            return None
        k = bisect_left(hit[0], start)
        if k == len(hit[0]):
            return None
        return hit[0][k], hit[1][k], hit[2][k]


def _php_blank_interp_region(
    chars: list[str], source: str, start: int, end: int, *,
    keep_strings: bool,
) -> None:
    r"""Blank the interpolating PHP string/heredoc body
    ``chars[start:end]``, keeping ``{$…}`` complex-syntax expressions
    visible as code. Escapes pair-blank (``\{$`` is data); simple
    ``$ident``/``${name}`` interpolation stays data (residual — a
    bare variable mention cannot spell a call)."""
    j = start
    while j < end:
        c = source[j]
        if c == "\\":
            if source.startswith("{$", j + 1):
                # PHP defines no \{ escape in double-quoted strings:
                # the backslash is literal DATA and the interpolation
                # still executes — consuming the pair would swallow a
                # live call (the f-string walker's brace rule).
                if not keep_strings and chars[j] != "\n":
                    chars[j] = " "
                j += 1
                continue
            if not keep_strings:
                for k in (j, j + 1):
                    if k < end and chars[k] != "\n":
                        chars[k] = " "
            j += 2
            continue
        if source.startswith("{$", j):
            j = _php_complex_expr(chars, source, j,
                                  keep_strings=keep_strings)
            continue
        if not keep_strings and chars[j] != "\n":
            chars[j] = " "
        j += 1


def _php_dq_end(
    chars: list[str], source: str, i: int, *, keep_strings: bool,
    multiline: bool = True, on_eof: Callable[[], None] | None = None,
) -> int:
    """Consume the PHP double-quoted or backtick string opened at
    ``i`` (the quote char there is the closer), blanking literal text
    while ``{$…}`` complex-syntax interpolation stays visible (it is
    executable code — `{$obj->method($arg)}` calls the method). The
    walk runs in BOTH view modes: only it finds the true closing quote
    once a kept expression contains a nested ``"``. PHP strings span
    lines, so literal text runs to the closer (end of input when
    unterminated) — a newline stop re-opened string state on the
    closing line and let a continuation-line ``?>`` read as a close
    tag (``multiline=False`` is the fallback rescan's single-line
    stop). ``on_eof`` is called when the string runs off the end of
    the input. Returns the index just past the closing quote."""
    n = len(source)
    quote = source[i]
    j = i + 1

    def blank1(k: int) -> None:
        if not keep_strings and chars[k] != "\n":
            chars[k] = " "

    while j < n:
        c = source[j]
        if c == "\\":
            if source.startswith("{$", j + 1):
                # No \{ escape in PHP double quotes — the backslash
                # is data, the interpolation executes (see
                # _php_blank_interp_region).
                blank1(j)
                j += 1
                continue
            blank1(j)
            if j + 1 < n:
                blank1(j + 1)
            j += 2
            continue
        if source.startswith("{$", j):
            j = _php_complex_expr(chars, source, j,
                                  keep_strings=keep_strings)
            continue
        if c == quote:
            return j + 1
        if c == "\n" and not multiline:
            return j + 1
        blank1(j)
        j += 1
    if on_eof is not None:
        on_eof()
    return n


def _php_complex_expr(
    chars: list[str], source: str, j: int, *, keep_strings: bool,
) -> int:
    """Skip the ``{$…}`` complex-syntax interpolation opened at ``j``
    (kept visible as code); nested string literals inside it blank
    their own contents. Returns the index just past the matching
    ``}``; an unterminated expression keeps the remainder visible
    (over-inclusion, never a swallow)."""
    n = len(source)
    depth = 0
    while j < n:
        c = source[j]
        if c == "{":
            depth += 1
            j += 1
        elif c == "}":
            depth -= 1
            j += 1
            if depth == 0:
                return j
        elif c in ("'", '"'):
            e = _string_end(source, j, c)
            for k in range(j + 1, min(e, n) - 1):
                if not keep_strings and chars[k] != "\n":
                    chars[k] = " "
            j = e
        else:
            j += 1
    return n


# d-char set per the C++ grammar: no space/parens/backslash/control
# AND no quote — admitting `"` let an ill-formed `R"abc"` shape
# (macro / #if-0 text) false-open a raw string and blank to EOF.
_CPP_RAW_DELIM_RE = re.compile(r"([^ ()\\\t\r\n\v\f\"]{0,16})\(")

#: Keywords a `/` may directly follow while still opening a REGEX
#: literal (value position). Closed JS/TS grammar taxonomy, not a
#: learned name vocabulary.
_JS_REGEX_PRECEDING_KEYWORDS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete",
    "void", "do", "else", "case", "yield", "await", "throw",
})


#: Keywords whose parenthesised head ends a statement head: a `/` right
#: after their `)` starts an expression (a regex), not a division.
_JS_CONTROL_HEAD_KEYWORDS = frozenset({"if", "while", "for", "with"})


def _js_member_mark(chars: list[str], m: int) -> bool:
    """True when the character at ``m`` makes the following name a
    member or private name: a ``#``, or a single ``.``/``?.`` — not the
    last dot of a spread ``...`` and not a numeric literal's trailing
    dot (``1.``), after which a keyword is still a keyword."""
    if m < 0:
        return False
    if chars[m] == "#":
        return True
    if chars[m] != ".":
        return False
    if m >= 2 and chars[m - 1] == "." and chars[m - 2] == ".":
        return False  # the last dot of a spread `...`
    return not _js_dot_in_number(chars, m)


def _js_dot_in_number(chars: list[str], m: int) -> bool:
    """True when the ``.`` at ``m`` belongs to a numeric literal, judged
    by lexing the literal per ECMAScript (not Annex B): the token run
    around it (word characters, dots, and an exponent sign) is
    re-tokenised from its start. A decimal literal takes at most one
    ``.`` (``1.`` keeps a trailing dot); prefixed (``0x``/``0b``/``0o``)
    and BigInt literals take none; the ``.`` after a complete literal
    (``1.5.``, ``1e3.``, ``0b1.``, ``1..``) is a member access.
    Residual: an Annex-B legacy-octal literal (``07``) takes no dot,
    but ``07.`` is read here as a decimal with a trailing dot, so a
    keyword member after it (``07.if(a) / 2``) is misread."""
    s = m - 1
    while s >= 0:
        c = chars[s]
        if c == "." or _ident_char(c, True):
            s -= 1
        elif (c in "+-" and s >= 2 and chars[s - 1] in "eE"
                and (chars[s - 2].isdigit() or chars[s - 2] in "._")):
            s -= 1
        else:
            break
    j = s + 1
    prev_value = False
    while j <= m:
        c = chars[j]
        if "0" <= c <= "9" or (
                c == "." and not prev_value and j + 1 < len(chars)
                and "0" <= chars[j + 1] <= "9"):
            end = _js_number_end(chars, j)
            if j <= m < end:
                return True
            j, prev_value = end, True
        elif _ident_char(c, True):
            while j <= m and _ident_char(chars[j], True):
                j += 1
            prev_value = True
        else:
            j += 1  # a dot (or exponent sign) between tokens
            prev_value = False
    return False


def _js_number_end(chars: list[str], j: int) -> int:
    """Index just past the decimal part of the ECMAScript numeric
    literal starting at ``j`` (a digit, or a ``.`` followed by a digit).
    A prefixed literal (``0x1F``/``0b1``/``0o7``) ends here after its
    ``0``; the caller reads the rest as a word, and a dot after it is a
    member access either way (prefixed literals take no dot)."""
    n = len(chars)

    def digits(k: int) -> int:
        while k < n and (chars[k].isdigit() and chars[k] <= "9"
                         or chars[k] == "_"):
            k += 1
        return k

    if chars[j] == ".":
        k = digits(j + 1)
        fraction = True
    else:
        k = digits(j)
        fraction = False
        if k < n and chars[k] == ".":
            k = digits(k + 1)
            fraction = True
    if k < n and chars[k] in "eE":
        e = k + 1
        if e < n and chars[e] in "+-":
            e += 1
        if e < n and "0" <= chars[e] <= "9":
            return digits(e)
    if not fraction and k < n and chars[k] == "n":
        return k + 1
    return k


def _js_control_paren(chars: list[str], i: int) -> bool | None:
    """True when the ``(`` at ``i`` opens an ``if``/``while``/``for``/
    ``with`` head (``for await (`` too). Read on the view, so comments
    between keyword and ``(`` are already blanked. A keyword preceded
    by ``.``/``?.``/``#`` is a member or private name — a call
    expression, whose ``)`` is followed by division. (A method or
    object-literal key named like a keyword is followed by ``{``, never
    by ``/``, so it cannot reach the regex decision.) None — undecided —
    when an identifier ends in a keyword right after a non-ASCII
    character (``a\u200dif(``, a combining mark, ``a\u00b7while(``): an
    invisible or combining character is the whole difference between a
    call and a control head, so the reading is reported, not guessed."""
    e = _prev_sig(chars, i - 1, js=True)
    word, ws = _word_ending_at(chars, e, js=True)
    for kw in _JS_CONTROL_HEAD_KEYWORDS:
        if (len(word) > len(kw) and word.endswith(kw)
                and ord(word[-len(kw) - 1]) > 127):
            return None
    if word == "await":
        word, ws = _word_ending_at(
            chars, _prev_sig(chars, ws - 1, js=True), js=True)
        if word != "for":
            return False
    if word not in _JS_CONTROL_HEAD_KEYWORDS:
        return False
    k = _prev_sig(chars, ws - 1, js=True)
    return not _js_member_mark(chars, k)


def _js_regex_end(
    source: str, i: int, flag: Callable[[str], None] | None = None,
    last_close: tuple[int, str | None] = (-1, None),
    last_regex_end: int = -1,
    chars: list[str] | None = None,
    rx_state: list[int] | None = None,
) -> int | None:
    """Index just past the regex literal opened by the ``/`` at
    ``i``, or None when this position reads as division (or the
    candidate does not close on its own line — regex literals are
    single-line, so scanning on as code is the conservative
    fallback). Position rule (the standard lexer heuristic): after
    a value ender (identifier, number, ``)``, ``]``, quote) a ``/``
    divides; after an operator/opener/keyword/line start it opens a
    regex. Escapes and ``[...]`` classes (where ``/`` is literal)
    are honoured. After ``)`` the reading depends on what the paren
    closed: an ``if``/``while``/``for``/``with`` head is followed by a
    statement (regex), any other ``)`` by an operator (division).
    ``last_close`` is the scanner's record of the most recent ``)``
    (position, ``"control"``/``"expr"``, or None when it had no open
    ``(``) — tracked on the forward scan, so parens inside strings,
    comments and regexes never count. When the kind is unknown the
    division reading is kept and ``js-regex-after-paren`` is reported
    through ``flag``."""
    if source.startswith("//", i) or source.startswith("/*", i):
        return None
    view = chars if chars is not None else list(source[:i])
    k = _prev_sig(view, i - 1, js=True)
    if k >= 1 and view[k] in "+-" and view[k - 1] == view[k]:
        # After `++`/`--` (postfix: division; prefix before a regex is
        # rare and odd) the view does not guess: division — code shown
        # — and reported.
        if flag is not None:
            flag("js-regex-or-division")
        return None
    if k >= 0 and k + 1 == last_regex_end:
        # The `/` closing a regex literal is a value ender: what
        # follows it divides. Across a newline or comment that is
        # still division (no ASI before `/`), but reported: the view
        # renders it as division and says so.
        if flag is not None and any(
                c in _JS_LINE_TERMINATORS or not _js_is_ws(c)
                for c in source[k + 1:i]):
            flag("js-regex-or-division")
        return None
    # The previous significant token, read on the view: comments are
    # blanked and newlines skipped (no ASI happens before a `/`, so a
    # value ender on an earlier line still makes it a division).
    j = k
    if j >= 0:
        prev = view[j]
        if _ident_char(prev, True):
            word, ws = _word_ending_at(view, j, js=True)
            if word[0].isdigit():
                return None
            if word not in _JS_REGEX_PRECEDING_KEYWORDS:
                return None
            # A keyword spelled as a property or private name
            # (`traffic.in / 1024`, `obj?.typeof / 2`, `this.#delete`)
            # is an identifier: division follows.
            m = _prev_sig(view, ws - 1, js=True)
            if _js_member_mark(view, m):
                return None
        elif prev == ")":
            kind = last_close[1] if last_close[0] == j else None
            if kind != "control":
                if kind is None and flag is not None:
                    flag("js-regex-after-paren")
                return None
        elif prev in "]\"'`":
            return None
    retry = rx_state is not None and i < rx_state[0]
    bound = _JS_REGEX_RETRY_LEN if retry else _JS_REGEX_MAX_LEN
    stop = min(len(source), i + 1 + bound)
    body = _JS_REGEX_BODY_RE.match(source, i + 1, stop)
    if body is not None:
        return body.end()
    if rx_state is not None and not retry:
        lt = _JS_LT_RE.search(source, i + 1)
        rx_state[0] = len(source) if lt is None else lt.start()
    if (stop < len(source) and flag is not None
            and _JS_LT_RE.search(source, i + 1, stop) is None):
        # No close within the length bound (and no line end): not
        # followed further — division, code shown, reported.
        flag("js-regex-or-division")
    return None


def _cpp_raw_delim(source: str, i: int) -> str | None:
    """The raw-string delimiter when the quote at ``i`` opens a C/C++
    ``R"delim(`` literal (optionally ``u8``/``u``/``U``/``L``
    prefixed), else None. The prefix must not be the tail of a longer
    identifier."""
    j = i - 1
    if j < 0 or source[j] != "R":
        return None
    k = j - 1
    if k >= 1 and source[k] == "8" and source[k - 1] == "u":
        k -= 2
    elif k >= 0 and source[k] in "uUL":
        k -= 1
    if k >= 0 and (source[k].isalnum() or source[k] == "_"):
        return None
    m = _CPP_RAW_DELIM_RE.match(source, i + 1)
    return m.group(1) if m else None


def _rust_raw_hashes(source: str, i: int) -> int | None:
    """Hash count when the quote at ``i`` opens a Rust raw string
    (``r"…"``, ``r#"…"#``, ``br##"…"##``, any hash depth), else
    None."""
    j = i - 1
    hashes = 0
    while j >= 0 and source[j] == "#":
        hashes += 1
        j -= 1
    if j < 0 or source[j] != "r":
        return None
    k = j - 1
    if k >= 0 and source[k] == "b":
        k -= 1
    if k >= 0 and (source[k].isalnum() or source[k] == "_"):
        return None
    return hashes


def _java_text_block_end(
    source: str, i: int, *, escapes: bool = True,
    on_eof: Callable[[], None] | None = None,
) -> int:
    """Index just past the ``\\\"\\\"\\\"`` closing the triple-quoted
    block opened at ``i``, or end of input. ``escapes`` selects the
    language's escape model: Java text blocks honour backslash
    escapes; Kotlin raw strings and C# raw string literals give the
    backslash no meaning (honouring escapes there let a trailing
    ``\\\"\\\"\\\"`` push the close past the real terminator — the
    swallow direction)."""
    n = len(source)
    j = i + 3
    while j < n:
        if escapes and source[j] == "\\":
            j += 2
            continue
        if source.startswith('"""', j):
            return j + 3
        j += 1
    if on_eof is not None:
        on_eof()
    return n


def _nested_block_comment_end(
    source: str, i: int, *, on_eof: Callable[[], None] | None = None,
) -> int:
    """Index just past the ``*/`` closing the NESTING block comment
    opened at ``i`` (Kotlin/Swift grammar: interior ``/*`` opens a
    nested level and its ``*/`` closes only that level), or end of
    input when unterminated (comment-to-EOF, matching both
    compilers)."""
    n = len(source)
    depth = 1
    j = i + 2
    while j < n:
        if source.startswith("/*", j):
            depth += 1
            j += 2
        elif source.startswith("*/", j):
            depth -= 1
            j += 2
            if depth == 0:
                return j
        else:
            j += 1
    if on_eof is not None:
        on_eof()
    return n


def _csharp_verbatim_prefix(source: str, i: int) -> bool:
    """True when the quote at ``i`` opens a C# verbatim string —
    directly preceded by ``@`` (optionally interleaved with the
    interpolation sigil: ``$@"`` / ``@$"``). ``@`` cannot appear
    inside an identifier, so no longer-identifier tail check is
    needed."""
    j = i - 1
    saw_at = False
    while j >= 0 and source[j] in "@$":
        if source[j] == "@":
            saw_at = True
        j -= 1
        if i - j > 2:
            break
    return saw_at


def _csharp_verbatim_end(
    source: str, i: int, *, on_eof: Callable[[], None] | None = None,
) -> int:
    """Index just past the quote closing the C# verbatim string
    opened at ``i``: multi-line, ``\"\"`` doubling spells a literal
    quote, backslash has no escape meaning. Unterminated runs to end
    of input."""
    n = len(source)
    j = i + 1
    while j < n:
        if source[j] == '"':
            if j + 1 < n and source[j + 1] == '"':
                j += 2
                continue
            return j + 1
        j += 1
    if on_eof is not None:
        on_eof()
    return n


def _js_regex_flags_end(source: str, j: int) -> int:
    """Index past the flag letters following a regex literal's closing
    ``/`` at ``j - 1``."""
    while j < len(source) and (source[j].isalnum() or source[j] in "_$"):
        j += 1
    return j


#: Template literals nested inside `${…}` deeper than this are not
#: followed: the rest of the input is shown as code and reported as an
#: unterminated template (no recursion-limit crash on hostile input).
_JS_TEMPLATE_MAX_DEPTH = 200


def _template_literal(
    source: str, chars: list[str], i: int, blank_str,
    on_eof: Callable[[], None] | None = None,
    flag: Callable[[str], None] | None = None,
    nest: int = 0,
    rx_state: list[int] | None = None,
) -> int:
    """Consume the JS/TS template literal opened by the backtick at
    ``i``: string content blanks (escape-aware), while ``${…}``
    interpolation is scanned as CODE — nested strings, templates, and
    comments and regex literals inside it get their own treatment
    (regex literals with the main scan's position rule — not lexing
    them let a quote in ``${/'/.source}`` open a string over live
    code). Blanking the
    interpolation would hide executable code from receipt consumers
    (the swallow direction). Returns the index just past the closing
    backtick (or end of input). Past ``_JS_TEMPLATE_MAX_DEPTH`` nested
    levels the walk stops: the remainder stays visible and ``on_eof``
    reports it."""
    n = len(source)
    if nest >= _JS_TEMPLATE_MAX_DEPTH:
        if on_eof is not None:
            on_eof()
        return n
    j = i + 1
    while j < n:
        ch = source[j]
        if ch == "\\":
            blank_str(j, min(j + 2, n))
            j += 2
            continue
        if ch == "`":
            return j + 1
        if ch == "$" and source.startswith("${", j):
            j += 2
            depth = 1
            last_rex = last_paren = -1
            while j < n and depth:
                c2 = source[j]
                if c2 == "{":
                    depth += 1
                    j += 1
                elif c2 == "}":
                    depth -= 1
                    j += 1
                elif c2 == "`":
                    j = _template_literal(
                        source, chars, j, blank_str, on_eof=on_eof,
                        flag=flag, nest=nest + 1, rx_state=rx_state)
                elif c2 in ('"', "'"):
                    end = _string_end(source, j, c2)
                    blank_str(j + 1, end - 1)
                    j = end
                elif c2 == "/" and source.startswith("//", j):
                    end = source.find("\n", j)
                    end = n if end < 0 else end
                    _blank(chars, j, end)
                    j = end
                elif c2 == "/" and source.startswith("/*", j):
                    close = source.find("*/", j + 2)
                    end = n if close < 0 else close + 2
                    _blank(chars, j, end)
                    j = end
                elif c2 == ")":
                    # An interpolation holds expressions only: every
                    # `)` there closes an expression (division follows).
                    last_paren = j
                    j += 1
                elif c2 == "/" and (rex := _js_regex_end(
                        source, j, flag, (last_paren, "expr"), last_rex,
                        chars, rx_state)) is not None:
                    blank_str(j + 1, rex - 1)
                    j = last_rex = _js_regex_flags_end(source, rex)
                else:
                    j += 1
            continue
        blank_str(j, j + 1)
        j += 1
    if on_eof is not None:
        on_eof()
    return n
