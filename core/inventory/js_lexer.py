"""Single-pass JavaScript/TypeScript non-code blanker.

Shared lexical substrate for the inventory's JS/TS text detectors
(:mod:`core.inventory.dead_scope`, :mod:`core.inventory.module_load_abort`).
Those detectors make reachability rulings — dead-scope ranges and
whole-file module-load aborts are enforce-eligible hard-suppress
witnesses — so their view of "what is code" must match a real JS
lexer's on the shapes an untrusted repo can craft:

* A ``//`` inside a string must NOT start a comment (the two-phase
  comments-then-strings regex approach let ``"//"`` eat the rest of
  the line, including a dead-``if``'s real closing brace).
* A regex literal is opaque: quotes inside it (``/"/``) must not open
  a string, braces inside it (``/}}/``,) must not move brace depth.
* Template literals blank wholesale, including ``${…}`` interpolation
  (its braces must not move depth either).

:func:`blank_js_noncode` replaces every comment, string, template and
regex-literal character with a space, preserving newlines so line
arithmetic stays valid. What remains is code: braces, keywords,
operators, identifiers.

Regex-vs-division at ``/`` uses the standard lexer heuristic: a ``/``
begins a regex literal when the previous significant token cannot end
an expression — i.e. after an operator / opening bracket / statement
boundary / nothing, or after a keyword like ``return`` — and is
division after a value (identifier, number, ``)``, ``]``, or a string
we just blanked). A candidate regex whose closing ``/`` doesn't occur
on the same line is not a regex (regex literals cannot contain raw
newlines) and is left as division. Ambiguity is resolved toward the
real-lexer answer on all common shapes; the residual exotic corners
(``/`` in expression position right after ``)`` of an unbraced ``if``
header) fail toward treating it as division, which can only make the
consumers' conservative bail paths fire — never mint a bogus range.
"""

from __future__ import annotations

# Significant chars after which a `/` starts a regex literal: the
# previous token cannot end an expression. `}` is included — a `/`
# after a closing BLOCK brace is statement position (the object-literal
# `}` division case is vanishingly rare and mis-lexing it only blanks
# to the next `/` on that line).
_REGEX_PRECEDER_CHARS = frozenset("([{,;=:!&|?+-*%^~<>}")

# Keywords after which a `/` is a regex even though the preceding
# char is a word char.
_REGEX_PRECEDER_KEYWORDS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete",
    "void", "throw", "case", "do", "else", "yield", "await",
})


def _regex_end_on_line(s: list[str] | str, start: int) -> int | None:
    r"""Index just past the closing ``/`` of a regex literal starting
    at ``start`` (which must hold the opening ``/``), or ``None`` when
    no unescaped closing ``/`` occurs before the end of line — regex
    literals cannot contain raw newlines, so that means "not a regex".
    Handles ``\`` escapes and ``[…]`` character classes (an unescaped
    ``/`` inside a class does not terminate the literal)."""
    i = start + 1
    n = len(s)
    in_class = False
    while i < n:
        c = s[i]
        if c == "\n":
            return None
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "/":
            return i + 1
        i += 1
    return None


def blank_js_noncode(content: str) -> str:
    """Blank comments, strings, template literals and regex literals
    to spaces in one pass, preserving newlines. See module docstring.
    """
    out = list(content)
    n = len(out)
    i = 0
    last_significant: str | None = None
    # Index in ``out`` of the last significant char — used to read the
    # preceding word back for the keyword check.
    last_significant_idx = -1

    def _blank(idx: int) -> None:
        if out[idx] != "\n":
            out[idx] = " "

    while i < n:
        c = out[i]

        # ---- comments -------------------------------------------------
        if c == "/" and i + 1 < n and out[i + 1] == "/":
            while i < n and out[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and out[i + 1] == "*":
            _blank(i)
            _blank(i + 1)
            i += 2
            while i < n:
                if out[i] == "*" and i + 1 < n and out[i + 1] == "/":
                    out[i] = " "
                    out[i + 1] = " "
                    i += 2
                    break
                _blank(i)
                i += 1
            continue

        # ---- plain strings --------------------------------------------
        if c in "\"'":
            quote = c
            out[i] = " "
            i += 1
            while i < n:
                ch = out[i]
                if ch == "\\":
                    _blank(i)
                    if i + 1 < n:
                        _blank(i + 1)
                        i += 2
                    else:
                        i += 1
                    continue
                if ch == quote:
                    out[i] = " "
                    i += 1
                    break
                if ch == "\n":
                    # Unterminated string on this line — a real lexer
                    # errors here; stop the literal so the rest of the
                    # file is still lexed as code.
                    break
                _blank(i)
                i += 1
            # A string is a value: division follows it.
            last_significant = quote
            last_significant_idx = -1
            continue

        # ---- template literals (with ${…} nesting blanked) ------------
        if c == "`":
            out[i] = " "
            i += 1
            while i < n:
                ch = out[i]
                if ch == "\\":
                    _blank(i)
                    if i + 1 < n:
                        _blank(i + 1)
                        i += 2
                    else:
                        i += 1
                    continue
                if ch == "$" and i + 1 < n and out[i + 1] == "{":
                    _blank(i)
                    _blank(i + 1)
                    i += 2
                    depth = 1
                    while i < n and depth > 0:
                        ic = out[i]
                        if ic == "{":
                            depth += 1
                        elif ic == "}":
                            depth -= 1
                        _blank(i)
                        i += 1
                    continue
                if ch == "`":
                    out[i] = " "
                    i += 1
                    break
                _blank(i)
                i += 1
            last_significant = "`"
            last_significant_idx = -1
            continue

        # ---- regex literals -------------------------------------------
        if c == "/":
            starts_regex = (
                last_significant is None
                or last_significant in _REGEX_PRECEDER_CHARS
            )
            if (not starts_regex and last_significant_idx >= 0
                    and (last_significant.isalnum()
                         or last_significant in "_$")):
                # Read the word ending at last_significant_idx.
                j = last_significant_idx
                while j >= 0 and (out[j].isalnum() or out[j] in "_$"):
                    j -= 1
                word = "".join(out[j + 1:last_significant_idx + 1])
                starts_regex = word in _REGEX_PRECEDER_KEYWORDS
            if starts_regex:
                end = _regex_end_on_line(out, i)
                if end is not None:
                    while i < end:
                        _blank(i)
                        i += 1
                    # The literal is a value: division may follow.
                    last_significant = "/"
                    last_significant_idx = -1
                    continue
            # Division (or an unterminated candidate) — plain code char.
            last_significant = c
            last_significant_idx = i
            i += 1
            continue

        # ---- plain code ------------------------------------------------
        if not c.isspace():
            last_significant = c
            last_significant_idx = i
        i += 1

    return "".join(out)


__all__ = ["blank_js_noncode"]
