r"""Log-output sanitisation for untrusted strings.

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

`escape_nonprintable()` replaces such characters with `\xHH` so downstream
log consumers see inert, reviewable text. `has_nonprintable()` is the
predicate form for callers that prefer to reject the input outright (e.g.
the egress proxy's CONNECT-target parser fails-closed with a 400 Bad
Request rather than logging an escaped version of the bad target).

Python's `str.isprintable()` is the classifier — True for all ASCII
0x20-0x7E plus every Unicode codepoint whose general category is not
Cc/Cf/Cn/Co/Cs/Zl/Zp. ESC (0x1b), NUL, CR, LF, BEL, C1 controls
(0x80-0x9F), and Unicode line/paragraph separators are all rejected.

The label-preserving excerpting contract
----------------------------------------
For MIXED-AUTHORITY text artifacts — a trusted writer's label/marker
lines interleaved with untrusted quoted content (the dispatch
child-tail log is the canonical member) — escaping is necessary but
not sufficient. `escape_nonprintable(preserve_newlines=True)` passes
printable newlines through, so untrusted content can contain lines
SHAPED like the writer's own labels, and a windowed excerpt can drop
the genuine label while keeping the forged one. Three rules:

  1. Authority travels out-of-band. Facts the trusted side knows
     (exit status, ran/failed, timeout) are structured record fields;
     consumers re-emit them from parsed state, never recover them
     from artifact bytes.
  2. Tail windows re-attach the head. An excerpt of a mixed-authority
     artifact keeps the writer-authored line 1 plus an explicit
     elision marker — never a bare ``[-N:]`` over the whole document.
  3. In-band markers must be forgery-evident: either nonce-stamped
     (the dark_verify harness sentinel / merge_fence record-nonce
     precedents) or with untrusted body lines quoted/indented so
     marker-shaped lines cannot sit at column 0.

Single-field tail slices into structured records (a wholly-untrusted
``stderr_tail`` value) are NOT the class: there is no co-resident
authority to drop. Per-record log-line escaping keeps its documented,
weaker guarantee — only that no control byte reaches the TTY.
"""


_STRUCTURAL_WHITESPACE = frozenset(('\n', '\t'))


def escape_nonprintable(s: str, *, preserve_newlines: bool = False) -> str:
    r"""Return `s` with each non-printable character replaced by `\xHH`.

    Use this on any string that may contain attacker-influenced content
    before emitting it through `logging` (f-strings in log calls are the
    typical injection site) or writing it to a human-readable log file.

    Printable characters — including ASCII space and Unicode letters
    with legitimate non-ASCII categories — pass through unchanged.

    When `preserve_newlines` is True, ``\n`` and ``\t`` are kept as-is
    (they are structural in source code and multi-line prose). All other
    non-printable characters are still escaped.
    """
    if preserve_newlines:
        return "".join(
            c if c.isprintable() or c in _STRUCTURAL_WHITESPACE else _escape_char(c)
            for c in s
        )
    return "".join(
        c if c.isprintable() else _escape_char(c)
        for c in s
    )


def sanitise_for_terminal(s: str, *, max_len: int = 256) -> str:
    """Escape non-printables AND bound length — for attacker-influenced
    strings interpolated into operator-facing terminal output (e.g. the
    sandbox live-escalation stderr banners).

    `escape_nonprintable` alone is not enough there: printable content
    is unbounded (a hostile target can pick a 100 KB "hostname" or path
    to flood the operator's terminal, or to stuff instructions into a
    banner an LLM harness may later read), so the escaped string is
    truncated at `max_len` with an explicit elision marker rather than
    silently.
    """
    out = escape_nonprintable(s)
    if len(out) > max_len:
        out = out[:max_len] + f"...[+{len(out) - max_len} chars]"
    return out


def _escape_char(c: str) -> str:
    o = ord(c)
    if o <= 0xFF:
        return f"\\x{o:02x}"
    if o <= 0xFFFF:
        return f"\\u{o:04x}"
    return f"\\U{o:08x}"


def has_nonprintable(s: str) -> bool:
    """Return True if any character of `s` is non-printable.

    Predicate form of `escape_nonprintable()` — callers use this to
    decide whether to reject input outright (fail-closed) rather than
    sanitising and continuing. The egress proxy's CONNECT parser uses
    this: a hostname with ESC in it is almost certainly hostile, and
    rejecting is a stronger signal than accepting a sanitised version.
    """
    return any(not c.isprintable() for c in s)
