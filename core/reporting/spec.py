"""Report specification — domain-agnostic report structure."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


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
    metadata: Dict[str, str] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    table_columns: List[str] = field(default_factory=list)
    table_rows: List[Tuple] = field(default_factory=list)
    table_note: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    detail_title: str = "Details"
    detail_sections: List[ReportSection] = field(default_factory=list)
    sections: List[ReportSection] = field(default_factory=list)
    output_files: List[str] = field(default_factory=list)
