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
from core.security.prompt_envelope import _strip_autofetch_markup


_LINE_LEAD_MD_RE = re.compile(r'(?m)^([ \t]*)([`*_#]+)')

_ELLIPSIS = '…'


def sanitise_string(s: str, *, max_chars: int = 500) -> str:
    """Defang an LLM-returned string for safe rendering in reports / UI.

    `max_chars` is the post-escape length cap; the suffix ellipsis counts
    toward the cap (returned string is at most `max_chars` characters).

    Also strips autofetch markup. Pre-fix `sanitise_string` defanged
    line-leading markdown control chars but DIDN'T strip the
    autofetch markup family (`![](url)` images, `[text](javascript:)`
    links, `<img>`/`<iframe>`/`<script>` HTML tags, scheme-relative
    `//host` links). The input-side envelope already strips these
    from untrusted slot values BEFORE the model sees them, but
    the OUTPUT side leaked them through — the LLM could be
    coaxed into reproducing autofetch markup in its response,
    and that response landed in markdown reports / web UI without
    further sanitization. A finding renderer that opens the report
    in a browser then fired the autofetch (image src, iframe load,
    redirect link), exfiltrating context to the attacker-controlled
    URL.
    """
    s = _LINE_LEAD_MD_RE.sub(lambda m: m.group(1), s)
    s = _strip_autofetch_markup(s)
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
    emulators (``cat report.md``) — handled by `escape_nonprintable`.

    Fence-break protection: LLM-returned code can legitimately contain
    triple-backtick runs (nested fenced blocks in a docstring, code
    that quotes another fenced block, an LLM that hallucinated a
    fence inside its response). Pre-fix the function returned that
    code as-is; the wrapping renderer's outer ``` fence was then
    prematurely closed by the embedded ```, and everything AFTER
    that point spilled out of the code block — rendering as
    interpreted markdown (links autofetch, headings break layout,
    `<script>` tags execute on some preview surfaces).

    Insert a zero-width-space (U+200B) between the second and third
    backtick of any 3+ backtick run. Visually invisible to the
    operator reading the rendered markdown, but the markdown parser
    no longer sees a fence terminator. The reader's eye still sees
    ``` if they care, just not as a parse-relevant fence.
    """
    s = escape_nonprintable(s, preserve_newlines=True)
    # Defang fence-break: any run of 3+ backticks gets a ZWSP
    # inserted after the second char so the markdown parser sees
    # `` then `` ``` `` becomes `` `` U+200B ` `` etc. Use a regex
    # with a callback to handle 3, 4, 5+ backtick runs uniformly.
    import re as _re
    s = _re.sub(r"`{3,}", lambda m: "``​" + "`" * (len(m.group(0)) - 2), s)
    if len(s) > max_chars:
        s = s[: max_chars - 1] + _ELLIPSIS
    return s
