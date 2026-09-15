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
* ``${…}`` interpolation holds a full EXPRESSION — ES6 allows strings,
  nested templates, comments and regexes inside it, arbitrarily deep
  (`` `${`}`}` `` is valid and evaluates to ``"}"``). Interpolation
  code therefore re-enters the full lexer: counting raw braces alone
  would let a ``}`` inside a nested literal close the interpolation
  early, desynchronising the template-vs-code parity for the rest of
  the file — real code blanked as template data and template DATA
  lexed as code, which mints false dead-scope ranges and fabricated
  module-load aborts over live functions.

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
newlines) and is left as division.

The heuristic can still guess wrong (``/`` after an object literal's
``}`` or after postfix ``++``/``--`` is really division; ``/`` right
after ``)`` of an unbraced ``if`` header is really a regex). A wrong
guess in EITHER direction is parity-fatal when the candidate span
holds a quote or backtick: blanking a fake regex swallows the
quote/backtick, desynchronising string/template state for the REST of
the file — template data lexes as code, minting false dead ranges and
fabricated module-load aborts over live functions — while reading a
real regex as division lets its quote/backtick open a phantom literal
with the same effect. The lexer therefore refuses to guess: any regex
candidate whose span contains a quote or backtick raises
:class:`JsLexAmbiguityError`, and the consumers bail on the whole
file (no dead ranges, no abort — failing toward NO suppression).

Residual, stated honestly: a quote-free candidate can still be
mis-guessed. The damage is confined to the mis-lexed span on its one
line (in parseable JS the text between two same-statement ``/`` is a
balanced expression, so brace depth is unaffected); that can hide a
real abort or dead range on that line, but cannot flip lexical state
for the rest of the file.
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


class JsLexAmbiguityError(ValueError):
    """The lexer cannot blank this file with confidence.

    Raised when a regex-literal candidate span contains a quote or
    backtick: guessing regex-vs-division wrong there swallows (or
    conjures) a string/template delimiter and desynchronises lexical
    state for the rest of the file. Consumers making suppression
    rulings must catch this and bail on the whole file — report no
    dead ranges and no module-load abort — never fall back to a
    partially-blanked view.
    """


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

    Raises :class:`JsLexAmbiguityError` when a regex-literal candidate
    span contains a quote or backtick (regex-vs-division ambiguity the
    lexer refuses to guess through — see module docstring).
    """
    out = list(content)
    n = len(out)
    i = 0
    last_significant: str | None = None
    # Index in ``out`` of the last significant char — used to read the
    # preceding word back for the keyword check.
    last_significant_idx = -1
    # Stack of open ``${…}`` interpolations. Each entry counts the
    # ``{`` braces opened by CODE inside that interpolation and not yet
    # closed, so the ``}`` that really ends the interpolation (depth 0)
    # is distinguished from object-literal / block closers. The code
    # inside an interpolation runs through the main loop, so nested
    # strings, templates, comments and regexes lex with full fidelity.
    interp_depths: list[int] = []

    def _blank(idx: int) -> None:
        if out[idx] != "\n":
            out[idx] = " "

    def _scan_template(idx: int) -> tuple[int, bool]:
        """Blank template-literal TEXT from ``idx`` until the literal's
        closing backtick (returns ``(index-after, False)``) or a ``${``
        interpolation opener (blanked; returns ``(index-after, True)``
        so the caller re-enters code lexing). An unterminated template
        consumes to EOF, like a real lexer's error recovery."""
        while idx < n:
            ch = out[idx]
            if ch == "\\":
                _blank(idx)
                if idx + 1 < n:
                    _blank(idx + 1)
                    idx += 2
                else:
                    idx += 1
                continue
            if ch == "$" and idx + 1 < n and out[idx + 1] == "{":
                _blank(idx)
                _blank(idx + 1)
                return idx + 2, True
            if ch == "`":
                out[idx] = " "
                return idx + 1, False
            _blank(idx)
            idx += 1
        return idx, False

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

        # ---- template literals (interpolation re-enters the lexer) ----
        if c == "`":
            out[i] = " "
            i, entered_interp = _scan_template(i + 1)
            if entered_interp:
                # ``${`` starts a fresh expression: a ``/`` right after
                # it is a regex, and its brace depth starts at 0.
                interp_depths.append(0)
                last_significant = None
                last_significant_idx = -1
            else:
                # A template is a value: division follows it.
                last_significant = "`"
                last_significant_idx = -1
            continue

        # ---- interpolation closer: back to template text ---------------
        if c == "}" and interp_depths and interp_depths[-1] == 0:
            _blank(i)
            interp_depths.pop()
            i, entered_interp = _scan_template(i + 1)
            if entered_interp:
                interp_depths.append(0)
                last_significant = None
                last_significant_idx = -1
            else:
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
                    if any(ch in "`\"'" for ch in out[i + 1:end - 1]):
                        # A quote/backtick inside the candidate span:
                        # a wrong regex-vs-division guess here flips
                        # string/template parity for the rest of the
                        # file (escaped or not — blanking swallows the
                        # delimiter either way). Refuse to guess.
                        raise JsLexAmbiguityError(
                            "regex-vs-division candidate span contains "
                            "a quote or backtick"
                        )
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
            if interp_depths:
                # Track code braces inside the innermost ${…} so its
                # real closer (depth 0, handled above) is recognised.
                if c == "{":
                    interp_depths[-1] += 1
                elif c == "}":
                    interp_depths[-1] -= 1
            last_significant = c
            last_significant_idx = i
        i += 1

    return "".join(out)


__all__ = ["JsLexAmbiguityError", "blank_js_noncode"]
