"""Sanitized source views — comments and string literals blanked.

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
"""

from __future__ import annotations

# Extensions handled by the hash-comment (Python/shell-style) scanner.
_HASH_COMMENT_EXTS = (
    ".py", ".pyi", ".sh", ".bash", ".rb", ".pl", ".tcl",
    ".yaml", ".yml", ".toml",
)

# C-family extensions that also use backtick strings (Go raw strings,
# JS/TS template literals).
_BACKTICK_EXTS = (".go", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

# Language-id routing for callers that already know the language
# (checkers holding an inventory language id or a tree-sitter grammar
# name rather than a file path).
_HASH_COMMENT_LANGS = frozenset({
    "python", "ruby", "shell", "bash", "perl", "yaml", "toml",
})
_BACKTICK_LANGS = frozenset({
    "go", "javascript", "typescript", "tsx", "jsx",
})


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
        return _strip_c_family(
            source, backtick_strings=lang in _BACKTICK_LANGS,
        )
    lower = (file_path or "").lower()
    if lower.endswith(_HASH_COMMENT_EXTS):
        return _strip_python_like(source)
    backticks = lower.endswith(_BACKTICK_EXTS)
    return _strip_c_family(source, backtick_strings=backticks)


def _blank(chars: list[str], start: int, end: int) -> None:
    """Blank ``chars[start:end]``, keeping newlines."""
    for i in range(start, end):
        if chars[i] != "\n":
            chars[i] = " "


def _strip_c_family(source: str, *, backtick_strings: bool = False) -> str:
    chars = list(source)
    n = len(source)
    i = 0
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            end = source.find("\n", i)
            end = n if end < 0 else end
            _blank(chars, i, end)
            i = end
        elif ch == "/" and nxt == "*":
            close = source.find("*/", i + 2)
            end = n if close < 0 else close + 2
            _blank(chars, i, end)
            i = end
        elif ch in ('"', "'") or (backtick_strings and ch == "`"):
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
