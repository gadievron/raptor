"""Render raptor-emitted markdown (reports, hypotheses) to HTML.

Raptor's markdown artifacts (validation-report.md, forensic-report.md,
hypothesis-*.md, root-cause-hypothesis-*.md) are produced by raptor's
LLM agents. They contain headings, fenced code blocks, tables, bullet
lists, and inline links — rendering them as raw ``<pre>`` loses all
of that structure.

Security posture: raptor runs locally on the user's machine; its output
is trusted to the same extent the user trusts raptor. We do NOT escape
inline HTML blocks because raptor does emit some (mostly inside code
fences). Users facing untrusted raptor outputs should use ``markdown_raw``
or view the file via the file-serving route.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

import markdown as md

_EXTENSIONS = [
    "extra",         # tables, fenced code, footnotes, abbr, attr_list, def_list
    "sane_lists",    # stricter list parsing
    "admonition",    # !!! note blocks
]


@lru_cache(maxsize=1)
def _converter() -> md.Markdown:
    """Reused Markdown instance (extensions are expensive to set up)."""
    return md.Markdown(
        extensions=_EXTENSIONS,
        output_format="html",
    )


def render(text: Optional[str]) -> str:
    """Return the markdown source rendered to HTML. Empty input → ``""``."""
    if not text:
        return ""
    converter = _converter()
    try:
        html = converter.convert(text)
    finally:
        # Markdown instances are stateful across conversions — reset so
        # the next call gets a clean footnote counter etc.
        converter.reset()
    return html
