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
