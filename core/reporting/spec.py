"""Report specification — domain-agnostic report structure."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReportSection:
    """A named section with pre-rendered content."""
    title: str
    content: str


@dataclass
class ReportSpec:
    """Domain-agnostic report specification.

    Describes what to render, not how. The renderer turns this into
    markdown, console output, or other formats.
    """
    title: str = "Report"
    metadata: dict[str, str] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    table_columns: list[str] = field(default_factory=list)
    table_rows: list[tuple] = field(default_factory=list)
    table_note: str | None = None
    warnings: list[str] = field(default_factory=list)
    detail_title: str = "Details"
    detail_sections: list[ReportSection] = field(default_factory=list)
    sections: list[ReportSection] = field(default_factory=list)
    output_files: list[str] = field(default_factory=list)
