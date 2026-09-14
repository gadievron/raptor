"""Markdown neutralisation for untrusted values in operator reports.

report.md / review output / delta.md interpolate registry- and
manifest-sourced strings (package names, versions, fixed entries,
advisory ids/aliases, manifest paths). ``escape_nonprintable`` alone
defangs ANSI/BIDI/control bytes but passes PRINTABLE markdown
metacharacters — ``![x](url)`` renders as an active image beacon,
``[text](url)`` as a phishing link, and raw ``<img …>`` as HTML —
in any renderer that displays the report.

One mechanism, applied uniformly:

* :func:`neutralize_inline` — inert inline text: newlines collapsed,
  ``\\ | ` [ ] < >`` escaped (kills link/image/code/table/HTML
  syntax), non-printables defanged, length-capped.  Used for
  headings, bold spans, list prose, and (via ``diff.md_cell``) table
  cells.
* :func:`inline_code` — a code span with the payload's backticks
  neutralised, for values conventionally rendered as code (paths,
  version pins).  A code span is inert by construction once the
  payload cannot close it.

Free-text fields that need richer handling (advisory summaries /
details) keep ``core.security``'s ``sanitise_string`` /
``_strip_autofetch_markup`` treatment — those already strip the
link/image family.
"""

from __future__ import annotations

from typing import Any

from core.security.log_sanitisation import escape_nonprintable

# Length cap for interpolated values. Finding labels (eco:name@version
# + advisory id) and suppression reasons are long enough for
# legitimate values, short enough that an adversarial multi-kilobyte
# string can't balloon a report (or a PR comment past GitHub's cap).
MD_INLINE_LIMIT = 200


def neutralize_inline(value: Any, *, limit: int = MD_INLINE_LIMIT) -> str:
    """Neutralise an untrusted value for inline markdown output.

    Escapes the markdown/HTML structural characters (``|`` splits
    table rows; backticks open code spans; ``[``/``]`` form the
    link/image syntax whose URL part triggers autofetch beacons;
    ``<``/``>`` open raw HTML), collapses newlines (row/paragraph
    terminators), defangs non-printables, and length-caps, so every
    consumer (report.md, review output, baseline-delta.md,
    pr-comment.md, stdout) gets inert text.
    """
    text = str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    text = (
        text.replace("\\", "\\\\")
            .replace("|", "\\|")
            .replace("`", "\\`")
            .replace("[", "\\[")
            .replace("]", "\\]")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )
    text = escape_nonprintable(text)
    if len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return text


def inline_code(value: Any, *, limit: int = MD_INLINE_LIMIT) -> str:
    """Render an untrusted value as an inert markdown code span.

    Backticks in the payload are replaced (the span cannot be
    closed early), newlines collapsed, non-printables defanged,
    length capped.  Inside a code span the remaining markdown
    metacharacters are inert by construction.
    """
    text = str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    text = escape_nonprintable(text).replace("`", "'")
    if len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return f"`{text}`"


def code_cell(value: Any, *, limit: int = MD_INLINE_LIMIT) -> str:
    """An untrusted value as a code span INSIDE a table cell.

    ``inline_code`` alone is NOT table-safe: GFM parses table
    structure before inline spans, so a raw ``|`` inside a code span
    still splits the row (forged report cells). Escape it on top of
    the code-span neutralisation.
    """
    return inline_code(value, limit=limit).replace("|", "\\|")


__all__ = ["MD_INLINE_LIMIT", "code_cell", "inline_code", "neutralize_inline"]
