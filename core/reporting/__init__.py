"""Reporting package — shared report generation infrastructure.

Layer 1 (domain-agnostic):
    ReportSpec, ReportSection — report structure
    render_report() — markdown rendering
    render_console_table() — terminal box-drawing
    Formatting utilities

Layer 2 (findings-aware):
    build_findings_spec() — builds ReportSpec from vulnerability findings
    findings_summary() — 'Results at a Glance' table + counts
    get_display_status() — status derivation across pipeline formats
"""

from .spec import ReportSpec, ReportSection
from .renderer import render_report
from .console import render_console_table
from .formatting import get_display_status, title_case_type, truncate_path, format_elapsed
from .findings import (
    FINDINGS_COLUMNS,
    build_findings_spec,
    build_findings_rows,
    build_findings_summary,
    findings_summary_line,
    findings_summary,
)

# Public re-export surface (see module docstring for layering).
# Order matches the import groups above; both layers are intentionally
# exposed through the same hub because callers don't care which layer
# a helper lives in — they only care that it's `core.reporting`.
__all__ = [
    # Layer 1 — domain-agnostic report scaffolding
    "ReportSpec",
    "ReportSection",
    "render_report",
    "render_console_table",
    "get_display_status",
    "title_case_type",
    "truncate_path",
    "format_elapsed",
    # Layer 2 — findings-aware helpers
    "FINDINGS_COLUMNS",
    "build_findings_spec",
    "build_findings_rows",
    "build_findings_summary",
    "findings_summary_line",
    "findings_summary",
]
