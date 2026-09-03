"""Render raptor-emitted markdown (reports, hypotheses) to sanitised HTML.

Raptor's markdown artifacts (validation-report.md, forensic-report.md,
hypothesis-*.md, root-cause-hypothesis-*.md) are produced by raptor's
LLM agents. They contain headings, fenced code blocks, tables, bullet
lists, and inline links — rendering them as raw ``<pre>`` loses all
of that structure.

Security posture: report content is untrusted. It routinely embeds
model text, scanned-repo snippets, vendor report excerpts, and finding
payloads — exactly the places an attacker can plant markup. Templates
inject the result with ``| md | safe``, so everything returned from
:func:`render` MUST already be sanitised: the rendered HTML is cleaned
with ``nh3`` (strips script/style/event handlers/js: URLs, keeps
structural markup). If ``nh3`` is unavailable we fail closed and return
the source escaped inside ``<pre>`` rather than ever emitting raw HTML.
"""

from __future__ import annotations

import html as html_escape
from functools import lru_cache
from typing import Optional

import markdown as md

try:
    import nh3
except ImportError:  # pragma: no cover — exercised via monkeypatch in tests
    nh3 = None

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
    """Return the markdown source rendered to sanitised HTML.

    Empty input → ``""``. Without a sanitiser available, degrades to an
    escaped ``<pre>`` block — never unsanitised markup.
    """
    if not text:
        return ""
    if nh3 is None:
        return "<pre>" + html_escape.escape(text) + "</pre>"
    converter = _converter()
    try:
        rendered = converter.convert(text)
    finally:
        # Markdown instances are stateful across conversions — reset so
        # the next call gets a clean footnote counter etc.
        converter.reset()
    return nh3.clean(rendered)
