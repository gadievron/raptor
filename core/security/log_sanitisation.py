"""Log-output sanitisation for untrusted strings.

When RAPTOR logs a string that may contain attacker-influenced content —
scanned-repo filenames in argv, subprocess stderr / ASAN bug-type, CONNECT
hosts from the egress proxy's clients, SARIF/finding metadata — raw ANSI
escape sequences and other non-printable characters can:

  - Inject terminal escapes when an operator is watching live log output:
    colour flips, window-title spoofing, cursor-movement that overwrites
    prior lines with forged "all-clear" entries.
  - Corrupt line-oriented or JSON-structured log files (raw newlines,
    control bytes inside what the reader expects is one record).
  - Hide evidence from post-incident review by re-rendering log text.

`escape_nonprintable()` replaces such characters with `\\xHH` so downstream
log consumers see inert, reviewable text. `has_nonprintable()` is the
predicate form for callers that prefer to reject the input outright (e.g.
the egress proxy's CONNECT-target parser fails-closed with a 400 Bad
Request rather than logging an escaped version of the bad target).

Python's `str.isprintable()` is the classifier — True for all ASCII
0x20-0x7E plus every Unicode codepoint whose general category is not
Cc/Cf/Cn/Co/Cs/Zl/Zp. ESC (0x1b), NUL, CR, LF, BEL, C1 controls
(0x80-0x9F), and Unicode line/paragraph separators are all rejected.
"""


_STRUCTURAL_WHITESPACE = frozenset(('\n', '\t'))


def escape_nonprintable(s: str, *, preserve_newlines: bool = False) -> str:
    """Return `s` with each non-printable character replaced by `\\xHH`.

    Use this on any string that may contain attacker-influenced content
    before emitting it through `logging` (f-strings in log calls are the
    typical injection site) or writing it to a human-readable log file.

    Printable characters — including ASCII space and Unicode letters
    with legitimate non-ASCII categories — pass through unchanged.

    When `preserve_newlines` is True, ``\\n`` and ``\\t`` are kept as-is
    (they are structural in source code and multi-line prose). All other
    non-printable characters are still escaped.
    """
    if preserve_newlines:
        return "".join(
            c if c.isprintable() or c in _STRUCTURAL_WHITESPACE else f"\\x{ord(c):02x}"
            for c in s
        )
    return "".join(
        c if c.isprintable() else f"\\x{ord(c):02x}"
        for c in s
    )


def has_nonprintable(s: str) -> bool:
    """Return True if any character of `s` is non-printable.

    Predicate form of `escape_nonprintable()` — callers use this to
    decide whether to reject input outright (fail-closed) rather than
    sanitising and continuing. The egress proxy's CONNECT parser uses
    this: a hostname with ESC in it is almost certainly hostile, and
    rejecting is a stronger signal than accepting a sanitised version.
    """
    return any(not c.isprintable() for c in s)
