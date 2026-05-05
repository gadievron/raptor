"""Post-processing for untrusted strings before they reach reports / UI.

Pairs with prompt_envelope at the input side: where the envelope quarantines
input from being treated as instructions by the model, this module
quarantines untrusted output (LLM-returned strings, SARIF-sourced finding
fields from external scanners) from rendering surprises — terminal
injection, markdown auto-render, HTML/XSS — when the operator views
the rendered report.

Pipeline (sanitise_string):
  1. defang line-leading markdown control chars (`*_# at line start) on
     real newline boundaries — keeps prose readable mid-string while
     disabling block-level rendering
  2. escape ANSI / BIDI / control bytes (preserves `\\n`, `\\t` so multi-line
     prose still renders as paragraphs in reports)
  3. HTML-escape <, >, &, ", ' so embedded ``<script>`` / ``<img onerror>``
     can't execute when the markdown is rendered to HTML (GitHub preview,
     MkDocs, browser-rendered docs). Markdown allows raw HTML by default
     so this is essential, not optional.
  4. length-cap at max_chars with a single Unicode ellipsis (…)

For ``sanitise_code`` the line-leading defang is skipped (code legitimately
contains ``#include``, ``*ptr``, ``__attribute__``); the remaining steps
apply. Fenced ``` blocks isolate HTML rendering in well-behaved markdown
viewers, but a payload containing ``` could break out of the fence — the
HTML escape is defence-in-depth for that case.

Note: the /tmp/llm.md spec listed escape→strip→cap. We deviate to strip→
escape→html→cap because `core.security.log_sanitisation.escape_nonprintable`
treats `\\n` as non-printable and would convert it to `\\x0a`, which both
breaks the multi-line strip and prevents reports from showing line breaks.
The spec's *intent* (multi-line markdown defanged, ANSI/BIDI killed,
natural prose preserved) is preserved; only the literal order changed.
"""

from __future__ import annotations

import html
import re

from core.security.log_sanitisation import escape_nonprintable


_LINE_LEAD_MD_RE = re.compile(r'(?m)^([ \t]*)([`*_#]+)')

_ELLIPSIS = '…'


def sanitise_string(s: str, *, max_chars: int = 500, html_escape: bool = True) -> str:
    """Defang an untrusted string for safe rendering in reports / UI.

    ``max_chars`` is the post-escape length cap; the suffix ellipsis counts
    toward the cap (returned string is at most ``max_chars`` characters).

    ``html_escape`` (default True) HTML-escapes ``<``, ``>``, ``&``, ``"``,
    ``'`` so the output can't form active tags when rendered to HTML.
    Disable only for callers writing into a context that already isolates
    HTML (e.g. inside an attribute value that's being template-escaped
    elsewhere) — virtually all report-rendering callers want it on.
    """
    s = _LINE_LEAD_MD_RE.sub(lambda m: m.group(1), s)
    s = escape_nonprintable(s, preserve_newlines=True)
    if html_escape:
        s = html.escape(s, quote=True)
    if len(s) > max_chars:
        s = s[: max_chars - 1] + _ELLIPSIS
    return s


def sanitise_code(s: str, *, max_chars: int = 10_000, html_escape: bool = True) -> str:
    """Defang an untrusted code snippet for fenced-block rendering.

    Unlike sanitise_string, does NOT strip markdown control chars — code
    contains ``#include``, ``*ptr``, ``__attribute__`` legitimately.
    Fenced code blocks (` ``` `) isolate markdown rendering in well-behaved
    viewers; the HTML escape is defence-in-depth against fence-break
    attacks (a payload containing ``` could close the fence and emit raw
    HTML that the renderer would then process).
    """
    s = escape_nonprintable(s, preserve_newlines=True)
    if html_escape:
        s = html.escape(s, quote=True)
    if len(s) > max_chars:
        s = s[: max_chars - 1] + _ELLIPSIS
    return s
