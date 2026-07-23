"""String-literal-aware comment stripping for source code.

Single chokepoint for "strip comments without touching string
literals."  The codebase had ~6 scattered implementations of this
pattern (jsonc, source_intel, inventory extractors, SCA parsers,
audit callsite consistency, staleness normalisation).  This module
is the canonical one; new consumers should import from here.

Each language handler is a character-by-character state machine that
tracks whether the cursor is inside a string literal.  Comment markers
inside strings are left untouched.  This is deliberately NOT a full
lexer — it handles the common cases that matter for cosmetic-change
detection and call-site analysis, not every edge case in the language
spec.

Known limitations:
- Python: raw strings (r"...") and f-strings with nested braces are
  handled correctly for quote tracking, but the ``#`` inside a
  formatted expression (``f"{x:#04x}"``) is not stripped (safe
  direction — treated as code, not comment).
- C-family: raw string literals (R"delim(...)delim" in C++11) are
  not handled; the opening ``"`` starts a string that never closes
  properly.  Rare in practice and the failure mode is safe (under-
  stripping, not over-stripping).
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "C_FAMILY_SUFFIXES",
    "strip_comments",
    "strip_c_comments",
    "strip_python_comments",
    "strip_shell_comments",
]

C_FAMILY_SUFFIXES = frozenset((
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx",
    ".java", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs",
    ".m", ".mm", ".kt", ".swift", ".cs", ".scala",
))


def strip_comments(text: str, filename: str) -> str:
    """Strip comments from source text, respecting string literals.

    Dispatches to the appropriate language handler based on file
    extension.  Unknown extensions return the text unchanged (safe
    direction — no stripping means no false-positive cosmetic
    classification).
    """
    suffix = Path(filename).suffix.lower()
    if suffix in (".py", ".pyw"):
        return strip_python_comments(text)
    if suffix in C_FAMILY_SUFFIXES:
        return strip_c_comments(text)
    if suffix in (".sh", ".bash", ".zsh"):
        return strip_shell_comments(text)
    return text


# -------------------------------------------------------------------
# C-family: //, /* */, respecting " and ' string literals
# -------------------------------------------------------------------

def strip_c_comments(text: str) -> str:
    """Strip C-family comments while preserving string/char literals."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_block = False

    while i < n:
        c = text[i]

        if in_block:
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                in_block = False
                i += 2
            else:
                i += 1
            continue

        if c == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if nxt == "*":
                in_block = True
                i += 2
                continue

        if c in ('"', "'"):
            quote = c
            out.append(c)
            i += 1
            while i < n:
                qc = text[i]
                out.append(qc)
                if qc == "\\" and i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                    continue
                if qc == quote:
                    i += 1
                    break
                i += 1
            continue

        out.append(c)
        i += 1

    return "".join(out)


# -------------------------------------------------------------------
# Python: # comments, respecting triple-quoted and regular strings
# -------------------------------------------------------------------

def strip_python_comments(text: str) -> str:
    """Strip Python comments while preserving string literals."""
    out: list[str] = []
    i = 0
    n = len(text)

    while i < n:
        c = text[i]

        if c in ('"', "'"):
            quote = c
            if i + 2 < n and text[i + 1] == quote and text[i + 2] == quote:
                triple = quote * 3
                out.append(triple)
                i += 3
                while i < n:
                    if text[i] == "\\" and i + 1 < n:
                        out.append(text[i])
                        out.append(text[i + 1])
                        i += 2
                        continue
                    if (i + 2 < n
                            and text[i] == quote
                            and text[i + 1] == quote
                            and text[i + 2] == quote):
                        out.append(triple)
                        i += 3
                        break
                    out.append(text[i])
                    i += 1
                continue
            out.append(c)
            i += 1
            while i < n:
                qc = text[i]
                out.append(qc)
                if qc == "\\" and i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                    continue
                if qc == quote:
                    i += 1
                    break
                i += 1
            continue

        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue

        out.append(c)
        i += 1

    return "".join(out)


# -------------------------------------------------------------------
# Shell: # comments, respecting ' and " string literals
# -------------------------------------------------------------------

def strip_shell_comments(text: str) -> str:
    """Strip shell comments while preserving string literals."""
    out: list[str] = []
    i = 0
    n = len(text)

    while i < n:
        c = text[i]

        if c == "'":
            out.append(c)
            i += 1
            while i < n and text[i] != "'":
                out.append(text[i])
                i += 1
            if i < n:
                out.append(text[i])
                i += 1
            continue

        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                qc = text[i]
                out.append(qc)
                if qc == "\\" and i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                    continue
                if qc == '"':
                    i += 1
                    break
                i += 1
            continue

        if c == "#":
            if i == 0 or text[i - 1] in (" ", "\t", "\n", ";", "(", "{"):
                while i < n and text[i] != "\n":
                    i += 1
                continue

        out.append(c)
        i += 1

    return "".join(out)
