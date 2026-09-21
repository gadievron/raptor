"""Markdown renderer for ReportSpec.

Rendering contract — who sanitises what:

* **This renderer** defangs the SINGLE-LINE slots itself: the spec
  title, metadata keys/values, summary cells, warnings, table cells,
  and section titles go through ``_md_heading`` / ``_md_table_cell``
  (single-line ``sanitise_string``), and output-file names through the
  same cell treatment. A NEW ``render_report`` caller therefore cannot
  leak raw heading/markup/control bytes through these slots even if it
  forgets to sanitise.
* **Section content** (``section.content`` and ``table_note``) is
  producer-built markdown — lists, tables and headings the producers
  deliberately constructed from already-sanitised fields — so the
  renderer must NOT strip its structure. It gets control-byte escaping
  only (``escape_nonprintable`` with newlines preserved); defanging
  the foreign-derived FIELDS inside it remains the producer's contract
  (see packages/exploitability_validation/report.py,
  core/reporting/findings.py).
"""

import re

from core.security.log_sanitisation import escape_nonprintable
from core.security.prompt_output_sanitise import sanitise_inline

from .spec import ReportSpec

_BARE_PIPE_RE = re.compile(r"(?<!\\)\|")


def _md_heading(value: object, *, max_chars: int = 300) -> str:
    """Single-line defang for headings / labels — newline-flattening,
    autofetch stripping, and control-byte escaping without eating
    legitimate label text (see sanitise_inline)."""
    return sanitise_inline(value, max_chars=max_chars)


def _md_table_cell(value: object, *, max_chars: int = 300) -> str:
    """Table-cell defang: heading treatment plus pipe escaping so a
    cell cannot terminate its row. sanitise_inline now entity-escapes
    in-value pipes itself, so the bare-pipe pass here is normally a
    no-op — kept as belt-and-braces so this helper's cell contract
    stands on its own. Only BARE pipes are escaped — producers that
    pre-escape must not be double-escaped into visible backslashes."""
    return _BARE_PIPE_RE.sub(r"\\|", _md_heading(value, max_chars=max_chars))


def render_report(spec: ReportSpec, separator: str = "---") -> str:
    """Render a ReportSpec as markdown.

    Args:
        spec: Report specification
        separator: Section separator string (default: markdown horizontal rule).
                   Pass None to disable separators.
    """
    lines = []

    def _sep() -> None:
        if separator is not None:
            lines.append(separator)
            lines.append("")

    # Title + metadata
    lines.append(f"# {_md_heading(spec.title)}")
    lines.append("")
    for key, value in spec.metadata.items():
        lines.append(f"**{_md_heading(key, max_chars=100)}:** {_md_heading(value)}")
    lines.append("")

    # Overview block: summary + warnings + main table
    has_overview = spec.summary or spec.warnings or (spec.table_columns and spec.table_rows)
    if has_overview:
        _sep()

    if spec.summary:
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        for key, value in spec.summary.items():
            lines.append(f"| {_md_table_cell(key, max_chars=100)} "
                         f"| {_md_table_cell(value)} |")
        lines.append("")

    # Warnings
    lines.extend(f"⚠️ **{_md_heading(warning, max_chars=500)}**"
                 for warning in spec.warnings)
    if spec.warnings:
        lines.append("")

    # Main data table
    if spec.table_columns and spec.table_rows:
        lines.append(_render_table(spec.table_columns, spec.table_rows))
        lines.append("")
        if spec.table_note:
            lines.append(escape_nonprintable(str(spec.table_note),
                                             preserve_newlines=True))
            lines.append("")

    # Detail sections (per-finding, per-crash, etc.)
    if spec.detail_sections:
        _sep()
        lines.append(f"## {_md_heading(spec.detail_title)}")
        lines.append("")
        for i, section in enumerate(spec.detail_sections):
            lines.append(f"### {_md_heading(section.title)}")
            lines.append("")
            lines.append(escape_nonprintable(str(section.content),
                                             preserve_newlines=True))
            lines.append("")
            if i < len(spec.detail_sections) - 1:
                _sep()

    # Extra sections (environment, stage F review, etc.)
    for section in spec.sections:
        _sep()
        lines.append(f"## {_md_heading(section.title)}")
        lines.append("")
        lines.append(escape_nonprintable(str(section.content),
                                         preserve_newlines=True))
        lines.append("")

    # Output files
    if spec.output_files:
        _sep()
        lines.append("## Output Files")
        lines.append("")
        lines.append("```")
        # Escape (a control byte in a name survives a plain ``` fence
        # when the file is catted) — but keep the fence itself intact.
        lines.extend(f"  {_md_heading(fname)}" for fname in spec.output_files)
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def _render_table(columns: list[str], rows: list[tuple]) -> str:
    """Render a markdown table. Every cell is defanged — rows routinely
    carry finding-derived text (titles, file paths, statuses)."""
    lines = []
    lines.append("| " + " | ".join(_md_table_cell(c, max_chars=100)
                                   for c in columns) + " |")
    lines.append("|" + "|".join("---" for _ in columns) + "|")
    lines.extend(
        "| " + " | ".join(_md_table_cell(c) for c in row) + " |"
        for row in rows
    )
    return "\n".join(lines)
