"""Post-processing for LLM-returned strings before they reach reports / UI.

Pairs with prompt_envelope at the input side: where the envelope quarantines
input from being treated as instructions by the model, this module
quarantines model output from rendering surprises (terminal-injection,
markdown auto-render) when the operator views findings.

Pipeline:
  1. defang line-leading markdown control chars (`*_# at line start) on
     real newline boundaries — keeps prose readable mid-string while
     disabling block-level rendering
  2. escape ANSI / BIDI / control bytes (preserves `\\n`, `\\t` so multi-line
     prose still renders as paragraphs in reports)
  3. length-cap at max_chars with a single Unicode ellipsis (…)

Note: the /tmp/llm.md spec listed escape→strip→cap. We deviate to strip→
escape→cap because `core.security.log_sanitisation.escape_nonprintable`
treats `\\n` as non-printable and would convert it to `\\x0a`, which both
breaks the multi-line strip and prevents reports from showing line breaks.
The spec's *intent* (multi-line markdown defanged, ANSI/BIDI killed,
natural prose preserved) is preserved; only the literal order changed.
"""

from __future__ import annotations

import re

from core.security.log_sanitisation import escape_nonprintable


_LINE_LEAD_MD_RE = re.compile(r'(?m)^([ \t]*)([`*_#]+)')

_ELLIPSIS = '…'


def sanitise_string(s: str, *, max_chars: int = 500) -> str:
    """Defang an LLM-returned string for safe rendering in reports / UI.

    `max_chars` is the post-escape length cap; the suffix ellipsis counts
    toward the cap (returned string is at most `max_chars` characters).
    """
    s = _LINE_LEAD_MD_RE.sub(lambda m: m.group(1), s)
    s = escape_nonprintable(s, preserve_newlines=True)
    if len(s) > max_chars:
        s = s[: max_chars - 1] + _ELLIPSIS
    return s


def sanitise_code(s: str, *, max_chars: int = 10_000) -> str:
    """Escape control chars in LLM-returned code for fenced-block rendering.

    Unlike sanitise_string, does NOT strip markdown control chars — code
    contains ``#include``, ``*ptr``, ``__attribute__`` legitimately.
    Fenced code blocks (` ``` `) already isolate markdown rendering; the
    remaining threat is ANSI/BIDI/control-byte injection via terminal
    emulators (``cat report.md``).
    """
    s = escape_nonprintable(s, preserve_newlines=True)
    if len(s) > max_chars:
        s = s[: max_chars - 1] + _ELLIPSIS
    return s
