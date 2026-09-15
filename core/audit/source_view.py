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
common denominator for C/C++/Java/Go/Rust/JS/TS).

The C-family scanner also blanks the two preprocessor-dead channels
with the same one-planted-line attacker capability as a comment:
``#if 0 … #endif`` regions (whole-condition constant-zero spellings
only — ``0``/``(0)``/``0x0``/``0L``/``00`` are dead in every build;
any macro-bearing condition, including a zero prefix like
``#if 0 || FOO``, is build-dependent and not judged here — that
residual is documented, not covered) and backslash-line-continued
``//`` comments
(splicing happens before comment recognition, so the continued line
is comment text to the compiler).
"""

from __future__ import annotations

import re

# Extensions handled by the hash-comment (Python/shell-style) scanner.
_HASH_COMMENT_EXTS = (
    ".py", ".pyi", ".sh", ".bash", ".rb", ".pl", ".tcl",
    ".yaml", ".yml", ".toml",
)

# C-family extensions that also use backtick strings (Go raw strings,
# JS/TS template literals).
_BACKTICK_EXTS = (".go", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

# JS/TS treat '...' as a full string literal. Everywhere else in the
# C family (C/C++/Java/Go/Rust) a single quote only ever opens a
# short char/rune literal — treating it as a to-end-of-line string
# made a Rust lifetime tick (&'a str) blank the rest of the line,
# forging absence receipts.
_SQ_STRING_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
_SQ_STRING_LANGS = frozenset({"javascript", "typescript", "tsx", "jsx"})

# Language-id routing for callers that already know the language
# (checkers holding an inventory language id or a tree-sitter grammar
# name rather than a file path).
_HASH_COMMENT_LANGS = frozenset({
    "python", "ruby", "shell", "bash", "perl", "yaml", "toml",
})
_BACKTICK_LANGS = frozenset({
    "go", "javascript", "typescript", "tsx", "jsx",
})


# Char-literal shape: 'x' or a short escape ('\n', '\'', '\x41').
_CHAR_LIT_RE = re.compile(r"'(?:\\[^\n]{1,3}|[^'\\\n])'")


def sanitized_view(
    source: str, file_path: str = "", *, language: str | None = None,
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
    """
    if not source:
        return source
    if language:
        lang = language.lower()
        if lang in _HASH_COMMENT_LANGS:
            return _strip_python_like(source)
        return _blank_if0_regions(_strip_c_family(
            source, backtick_strings=lang in _BACKTICK_LANGS,
            single_quote_strings=lang in _SQ_STRING_LANGS,
        ))
    lower = (file_path or "").lower()
    if lower.endswith(_HASH_COMMENT_EXTS):
        return _strip_python_like(source)
    return _blank_if0_regions(_strip_c_family(
        source, backtick_strings=lower.endswith(_BACKTICK_EXTS),
        single_quote_strings=lower.endswith(_SQ_STRING_EXTS),
    ))


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
    lines = view.split("\n")
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
    source: str, *,
    backtick_strings: bool = False,
    single_quote_strings: bool = False,
) -> str:
    chars = list(source)
    n = len(source)
    i = 0
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            end = source.find("\n", i)
            # Backslash-newline splicing happens BEFORE comment
            # recognition (C/C++/Java): a ``// … \`` comment
            # continues onto the next physical line, which is
            # comment text to the compiler — a guard "hidden"
            # there must blank like any other comment byte.
            while end > 0 and (
                source[end - 1] == "\\"
                or (source[end - 1] == "\r" and end > 1
                    and source[end - 2] == "\\")
            ):
                end = source.find("\n", end + 1)
            end = n if end < 0 else end
            _blank(chars, i, end)
            i = end
        elif ch == "/" and nxt == "*":
            close = source.find("*/", i + 2)
            end = n if close < 0 else close + 2
            _blank(chars, i, end)
            i = end
        elif ch == "'" and not single_quote_strings:
            # Char/rune literal only, and only when it has the
            # char-literal shape (closing quote within a couple of
            # characters, escapes allowed). A lone tick — a Rust
            # lifetime, an apostrophe in code — is NOT a literal and
            # must not swallow the rest of the line.
            end = _char_literal_end(source, i)
            if end is None:
                i += 1
            else:
                _blank(chars, i + 1, end - 1)
                i = end
        elif ch == '"' or ch == "'" or (backtick_strings and ch == "`"):
            end = _string_end(source, i, ch, raw=(ch == "`"))
            # Keep the delimiters so shapes like ``""`` stay visible;
            # blank only the contents.
            _blank(chars, i + 1, min(end, n) - 1 if end <= n else n)
            i = end
        else:
            i += 1
    return "".join(chars)


def _strip_python_like(source: str) -> str:
    chars = list(source)
    n = len(source)
    i = 0
    while i < n:
        ch = source[i]
        if ch == "#":
            end = source.find("\n", i)
            end = n if end < 0 else end
            _blank(chars, i, end)
            i = end
        elif ch in ('"', "'"):
            triple = source[i:i + 3] in ('"""', "'''")
            if triple:
                close = source.find(source[i:i + 3], i + 3)
                end = n if close < 0 else close + 3
                _blank(chars, i + 3, max(i + 3, end - 3))
                i = end
            else:
                end = _string_end(source, i, ch)
                _blank(chars, i + 1, min(end, n) - 1 if end <= n else n)
                i = end
        else:
            i += 1
    return "".join(chars)


def _char_literal_end(source: str, start: int) -> int | None:
    """Index just past a char-literal's closing quote, or None.

    Accepts the char-literal shape only: one plain character
    (``'x'``) or a short escape (``'\\n'``, ``'\\x41'`` — at most
    three characters after the backslash). Anything else is not a
    literal.
    """
    m = _CHAR_LIT_RE.match(source, start)
    return m.end() if m else None


def _string_end(source: str, start: int, quote: str, *, raw: bool = False) -> int:
    """Index just past the closing quote (or end of line/file).

    Unterminated single-line strings stop at the newline — a lone
    apostrophe in text must not swallow the rest of the file.
    """
    n = len(source)
    i = start + 1
    while i < n:
        ch = source[i]
        if ch == "\\" and not raw:
            i += 2
            continue
        if ch == quote:
            return i + 1
        if ch == "\n" and not raw:
            return i + 1
        i += 1
    return n
