"""Markdown renderer for ReportSpec."""

from typing import List, Tuple

from .spec import ReportSpec, ReportSection


def render_report(spec: ReportSpec, separator: str = "---") -> str:
    """Render a ReportSpec as markdown.

    Args:
        spec: Report specification
        separator: Section separator string (default: markdown horizontal rule).
                   Pass None to disable separators.
    """
    lines = []

    def _sep():
        if separator is not None:
            lines.append(separator)
            lines.append("")

    # Title + metadata
    lines.append(f"# {spec.title}")
    lines.append("")
    for key, value in spec.metadata.items():
        lines.append(f"**{key}:** {value}")
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
            lines.append(f"| {key} | {value} |")
        lines.append("")

    # Warnings
    for warning in spec.warnings:
        lines.append(f"⚠️ **{warning}**")
    if spec.warnings:
        lines.append("")

    # Main data table
    if spec.table_columns and spec.table_rows:
        lines.append(_render_table(spec.table_columns, spec.table_rows))
        lines.append("")
        if spec.table_note:
            lines.append(spec.table_note)
            lines.append("")

    # Detail sections (per-finding, per-crash, etc.)
    if spec.detail_sections:
        _sep()
        lines.append(f"## {spec.detail_title}")
        lines.append("")
        for i, section in enumerate(spec.detail_sections):
            lines.append(f"### {section.title}")
            lines.append("")
            lines.append(section.content)
            lines.append("")
            if i < len(spec.detail_sections) - 1:
                _sep()

    # Extra sections (environment, stage F review, etc.)
    for section in spec.sections:
        _sep()
        lines.append(f"## {section.title}")
        lines.append("")
        lines.append(section.content)
        lines.append("")

    # Output files
    if spec.output_files:
        _sep()
        lines.append("## Output Files")
        lines.append("")
        lines.append("```")
        for fname in spec.output_files:
            lines.append(f"  {fname}")
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def _render_table(columns: List[str], rows: List[Tuple]) -> str:
    """Render a markdown table."""
    lines = []
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("|" + "|".join("---" for _ in columns) + "|")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)
