"""Source-level pre-scan for LLM-generated PoC C/C++ before compilation.

Why this exists:

The LLM-generated PoC source flowing into ``ExploitValidator.validate_exploit``
is attacker-influenceable via prompt injection in scanned-target metadata,
finding descriptions, scanner output, etc. The anti-prompt-injection
initiative (PR #273 and follow-ups) is the primary defence at the prompt
side, but if a clever payload survives those layers and convinces the
generator LLM to emit C with ``#include "/etc/passwd"`` or similar, gcc
happily reads the file and leaks the first non-parseable line into stderr,
which then flows back to the refiner LLM. A live probe confirmed the
channel works today (see ``project_poc_source_analysis.md`` memory).

This module is a narrowly-scoped second line of defence: a regex pre-pass
that rejects exfiltration shapes in LLM-generated standalone PoCs. It is
NOT a general C source validator — it only encodes the constraint
"validate_exploit's PoCs don't need to read files outside their own
work_dir or the standard system include path". Generic C compilation
(libxml2 etc.) violates that constraint legitimately and would be wrongly
rejected; that's outside the scope of this consumer.

What we block:

  - ``#include "/abs/path"`` and ``#include </abs/path>`` — direct exfil
  - ``#include "../../traversing"`` — traversal escape from work_dir
  - ``#embed "/abs"`` / ``#embed "../trav"`` — C23 file embedding
  - ``__has_include(<abs>)`` / ``__has_include("../trav")`` — 1-bit oracle
  - ``#pragma GCC dependency "/abs"`` / ``"../trav"`` — stat-based oracle
  - ``.incbin "/abs"`` / ``.incbin "../trav"`` — assembler embed

Angle-bracket includes of bare names (``<sys/socket.h>``) pass through:
gcc resolves them via the toolchain include search path, not the source
directory, so they aren't a traversal vector. ``#include "foo.h"`` and
``#include "subdir/bar.h"`` also pass — same-dir or descending-only.

What we don't try to do:

  - Match obfuscated forms (macro-built paths, stringification tricks).
    Belt-and-braces only: a determined attacker who has already bypassed
    every prompt-injection defence is the threat model, and even then
    most exfil shapes are caught by the obvious patterns.
  - Block destructive runtime constructs (``system()``, ``unlink()``).
    Those are policed at runtime by the sandbox layer, not at source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SourceScanViolation:
    """One pattern match. ``message`` is suitable for surfacing to the
    refiner LLM as compilation-style feedback so it can iterate."""

    directive: str  # "#include", "#embed", "__has_include", etc.
    path: str       # the offending path string
    reason: str     # "absolute path" or "directory traversal"
    line_no: int    # 1-indexed source line


# Each (directive_label, regex) extracts the path argument from a
# preprocessor or assembler directive. Anchored to line start so we
# don't match inside string literals or comments by accident — multi-line
# block comments containing real ``#include`` directives are vanishingly
# rare in PoC source and aren't worth a full C tokenizer.

# Use ``[ \t\f\v]*`` rather than ``\s*`` for leading and intra-directive
# whitespace: ``\s`` includes ``\n`` and lets the regex engine anchor a
# match on a blank line preceding the directive, which throws the
# reported line number off by however many blank lines came before.
# Formfeed and vertical tab must be INCLUDED though — gcc treats both
# as horizontal whitespace before/inside a directive, so ``\f#include``
# is live to the preprocessor and must not slip past the scan.
#
# The directive introducer is ``(?:#|%:)``: ``%:`` is the standard C
# digraph for ``#`` and gcc processes ``%:include "/etc/passwd"``
# exactly like the plain spelling.
_WS = r'[ \t\f\v]'
_HASH = r'(?:#|%:)'
_DIRECTIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("#include",
     re.compile(rf'^{_WS}*{_HASH}{_WS}*include{_WS}*[<"]([^>"]+)[>"]', re.MULTILINE)),
    ("#embed",
     re.compile(rf'^{_WS}*{_HASH}{_WS}*embed{_WS}*[<"]([^>"]+)[>"]', re.MULTILINE)),
    ("#pragma GCC dependency",
     re.compile(
         rf'^{_WS}*{_HASH}{_WS}*pragma{_WS}+GCC{_WS}+dependency{_WS}+"([^"]+)"',
         re.MULTILINE,
     )),
    ("__has_include",
     re.compile(r'__has_include\s*\(\s*[<"]([^>"]+)[>"]\s*\)')),
    # ``.incbin "..."`` appears inside ``__asm__("...")`` blocks where the
    # C-string-escape ``\"`` survives into the source we scan. The
    # non-greedy ``[^"]+?`` and trailing ``\\?`` together capture the path
    # without a stray backslash artefact (else the LLM-facing message
    # would read ``/etc/passwd\``).
    (".incbin",
     re.compile(r'\.incbin\s+\\?"([^"]+?)\\?"')),
)


def _classify(path: str) -> str | None:
    """Return a violation reason for ``path``, or None if the path is OK.

    Decision:
      - absolute path (``/...`` or platform-equivalent) → block
      - any segment is ``..`` → block
      - else → allow
    """
    if path.startswith("/") or (len(path) >= 2 and path[1] == ":"):
        # POSIX absolute, or Windows drive-letter absolute
        return "absolute path"
    # Normalise separators and split — mixed ``/`` and ``\`` both possible
    # if a Windows-style path slipped through. We don't care which.
    parts = re.split(r"[/\\]", path)
    if any(p == ".." for p in parts):
        return "directory traversal"
    return None


# Raw-string introducer: the emitted tail must end with ``R`` (plus an
# optional encoding prefix) that is NOT the tail of a longer identifier
# — ``FOOBAR"..."`` is an identifier followed by an ordinary string.
# The ``^`` alternative only fires within the first three characters of
# the file (the longest prefix, ``u8R``, is three chars), so a 4-char
# lookback window can never mistake a truncated identifier for a
# start-of-file prefix.
_RAW_PREFIX_RE = re.compile(r'(?:^|[^0-9A-Za-z_])(?:u8|u|U|L)?R\Z')

# d-char-seq + opening paren: up to 16 d-chars, where a d-char is any
# character except parentheses, backslash and whitespace ([lex.string]).
_RAW_DELIM_RE = re.compile(r'[^()\\ \t\v\f\r\n]{0,16}\(')


def _skip_splices(source: str, j: int) -> int:
    """Return the first index at/after ``j`` that is not the start of a
    phase-2 line splice (backslash immediately followed by a newline)."""
    n = len(source)
    while j < n and source[j] == "\\":
        if source.startswith("\n", j + 1):
            j += 2
        elif source.startswith("\r\n", j + 1):
            j += 3
        else:
            break
    return j


def _match_raw_string(source: str, i: int, out: list[str]) -> int | None:
    """Try to consume a raw-string literal whose opening quote is at
    ``source[i]``, given the normalised text emitted so far in ``out``.

    Returns the index just past the closing quote and appends a
    placeholder (two quotes around the body's preserved newlines) to
    ``out``; returns None when this is not a well-formed raw-string
    literal. Both malformed shapes — no ``(`` within the 16-d-char
    limit, unterminated body — fall back to the caller's ordinary
    string handling, the over-inclusion-safe direction: text the
    compiler may treat as inert literal data gets SCANNED rather than
    trusted as inert.

    Everything between the quotes is consumed verbatim: phases 1-2 are
    reverted inside raw strings, so no splice handling applies to the
    delimiter or the body.
    """
    tail = "".join(out[-4:])[-4:]
    if not _RAW_PREFIX_RE.search(tail):
        return None
    m = _RAW_DELIM_RE.match(source, i + 1)
    if m is None:
        return None
    delim = m.group(0)[:-1]
    body_start = m.end()
    terminator = ")" + delim + '"'
    end = source.find(terminator, body_start)
    if end == -1:
        return None
    out.append('"')
    out.append("\n" * source.count("\n", body_start, end))
    out.append('"')
    return end + len(terminator)


def _normalise(source: str) -> str:
    r"""Approximate translation phases 2-3 so directive regexes see what
    the preprocessor sees.

    Two legal spellings the raw regexes miss:

      - ``#include \`` + newline + ``"path"`` — phase 2 splices
        backslash-newline continuations before directives are parsed.
      - ``#include/*x*/"path"`` — phase 3 replaces each block comment
        with a single space.

    The comment pass is a small state walk, not a regex substitution:
    ``/*`` inside a string literal or line comment must NOT open a
    comment, otherwise an attacker could hide a live directive inside
    text the stripper wrongly deletes (the compiler would still
    process it). C++ raw-string literals get the same treatment with
    their own grammar (``R"delim( ... )delim"``, optional ``u8``/``u``/
    ``U``/``L`` encoding prefix): the body is consumed as inert data —
    an embedded ``"`` must not pop the walker back to code state where
    a body ``/*`` opens a phantom comment that deletes a following
    live directive from the scanned view.

    Phase-2 splices are applied INLINE during the walk rather than as
    a global pre-pass, because the standard reverts phases 1-2 inside
    raw-string literals: a pre-spliced view can terminate a raw string
    early (a body ``)\`` + newline + ``"`` splices into the terminator
    ``)"``) and re-open the phantom-comment channel. Outside raw
    strings the inline rule is equivalent to the global pre-pass,
    including ``\\`` + newline inside ordinary strings (the second
    backslash splices away and the first escapes the next line's
    first character).

    Newlines inside block comments and raw-string bodies are preserved
    so reported line numbers stay aligned; spliced continuations do
    shift later line numbers by the number of splices above them,
    which is acceptable at PoC scale.
    """
    out: list[str] = []
    i = 0
    n = len(source)
    state = "code"  # code | string | char | line_comment | block_comment
    while i < n:
        c = source[i]
        # Phase-2 splice, all states (raw-string bodies never reach
        # this loop — they are consumed wholesale below).
        if c == "\\":
            j = _skip_splices(source, i)
            if j != i:
                i = j
                continue
        if state == "code":
            if c == '"':
                raw_end = _match_raw_string(source, i, out)
                if raw_end is not None:
                    i = raw_end
                    continue
                state = "string"
                out.append(c)
            elif c == "'":
                state = "char"
                out.append(c)
            elif c == "/":
                nxt = _skip_splices(source, i + 1)
                if source.startswith("*", nxt):
                    state = "block_comment"
                    out.append(" ")
                    i = nxt + 1
                    continue
                if source.startswith("/", nxt):
                    state = "line_comment"
                    out.append("//")
                    i = nxt + 1
                    continue
                out.append(c)
            else:
                out.append(c)
        elif state in ("string", "char"):
            quote = '"' if state == "string" else "'"
            if c == "\\":
                # The escaping backslash's operand sits past any
                # splices (``\\`` + newline + X escapes X).
                j = _skip_splices(source, i + 1)
                if j < n:
                    out.append("\\" + source[j])
                    i = j + 1
                    continue
                out.append(c)
                i += 1
                continue
            if c in (quote, "\n"):
                # A literal can't span a raw newline; drop back to code
                # so an unterminated quote can't swallow the file.
                state = "code"
            out.append(c)
        elif state == "line_comment":
            if c == "\n":
                state = "code"
            out.append(c)
        else:  # block_comment
            if c == "*":
                nxt = _skip_splices(source, i + 1)
                if source.startswith("/", nxt):
                    state = "code"
                    i = nxt + 1
                    continue
            if c == "\n":
                out.append("\n")  # keep line numbers aligned
        i += 1
    return "".join(out)


def scan(source: str) -> list[SourceScanViolation]:
    """Return all violations found in ``source``. Empty list = OK to compile."""
    source = _normalise(source)
    violations: list[SourceScanViolation] = []
    for directive, pattern in _DIRECTIVE_PATTERNS:
        for m in pattern.finditer(source):
            path = m.group(1)
            reason = _classify(path)
            if reason is None:
                continue
            line_no = source.count("\n", 0, m.start()) + 1
            violations.append(SourceScanViolation(
                directive=directive,
                path=path,
                reason=reason,
                line_no=line_no,
            ))
    return violations


def format_violations(violations: list[SourceScanViolation]) -> list[str]:
    """Render violations as compilation-error-shaped strings the refiner
    LLM can iterate against. Avoids exposing the security mechanism by
    framing the rejection as a coding-style requirement."""
    return [
        f"line {v.line_no}: {v.directive} with {v.reason!s} "
        f"(``{v.path}``) is not allowed; use a same-directory include or "
        f"a standard ``<header>`` instead"
        for v in violations
    ]
