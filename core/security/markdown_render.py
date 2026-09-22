"""One home for markdown-writer escaping discipline.

Every markdown report writer needs the same three slots defended, and
before this module each writer rolled its own helper for them
(``_md_escape_inline`` in core/project/report.py, ``_fenced`` in
core/audit/context.py, ``_fence`` in packages/diagram/renderer.py,
``_md_cell`` in cve-diff's markdown renderer, ...) — and the next
fresh writer used none of them. These wrappers are the discipline
home new writers adopt directly; they are thin, named projections of
:mod:`core.security.prompt_output_sanitise` (the canonical pipeline),
never a parallel engine:

* :func:`md_fence` — verbatim code/snippet inside a ``` fence.
  Fence-break defanged (ZWSP inside 3+ backtick runs), control/BIDI
  bytes escaped, length-capped. An embedded ``` cannot terminate the
  wrapping fence and spill live markdown.
* :func:`md_inline` — single-line slots: headings, labels, table
  cells. Newlines flattened, autofetch markup stripped, in-slot
  structure (``|``, backtick) entity-escaped, length-capped.
* :func:`md_prose` — multi-line free text (finding messages,
  descriptions). Line-leading markdown structure defanged, autofetch
  markup stripped, control bytes escaped, newlines preserved,
  length-capped.

All three are recognised sanitisers in
:mod:`core.security.report_writer_audit` (``_SANITISERS``), so a
writer that routes its foreign values through them passes the writer
gate by construction.
"""

from __future__ import annotations

from typing import Any

from core.security.prompt_output_sanitise import (
    sanitise_code,
    sanitise_inline,
    sanitise_string,
)


def md_fence(value: Any, *, max_chars: int = 10_000) -> str:
    """Defang a value for rendering inside a fenced code block."""
    return sanitise_code(str(value), max_chars=max_chars)


def md_inline(value: Any, *, max_chars: int = 300) -> str:
    """Defang a value for a single-line markdown slot (heading,
    label, table cell)."""
    return sanitise_inline(str(value), max_chars=max_chars)


def md_prose(value: Any, *, max_chars: int = 4_000) -> str:
    """Defang multi-line free text for markdown body rendering."""
    return sanitise_string(str(value), max_chars=max_chars)


__all__ = ["md_fence", "md_inline", "md_prose"]
