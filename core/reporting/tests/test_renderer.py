#!/usr/bin/env python3
"""Tests for markdown report renderer."""

import unittest
from core.reporting.spec import ReportSpec, ReportSection
from core.reporting.renderer import render_report


class TestRenderReport(unittest.TestCase):

    def test_minimal(self):
        spec = ReportSpec(title="Test")
        result = render_report(spec)
        self.assertIn("# Test", result)

    def test_metadata(self):
        spec = ReportSpec(
            title="Report",
            metadata={"Target": "`/tmp/test`", "Date": "2026-04-04"},
        )
        result = render_report(spec)
        self.assertIn("**Target:** `/tmp/test`", result)
        self.assertIn("**Date:** 2026-04-04", result)

    def test_summary(self):
        spec = ReportSpec(summary={"Files": 10, "Findings": 5})
        result = render_report(spec)
        self.assertIn("| Metric | Value |", result)
        self.assertIn("| Files | 10 |", result)

    def test_table(self):
        spec = ReportSpec(
            table_columns=["#", "Name"],
            table_rows=[("1", "foo"), ("2", "bar")],
            table_note="A note.",
        )
        result = render_report(spec)
        self.assertIn("| # | Name |", result)
        self.assertIn("| 1 | foo |", result)
        self.assertIn("A note.", result)

    def test_warnings(self):
        spec = ReportSpec(warnings=["Something is wrong"])
        result = render_report(spec)
        self.assertIn("⚠️ **Something is wrong**", result)

    def test_detail_sections(self):
        spec = ReportSpec(detail_sections=[
            ReportSection("Finding 1", "Some detail"),
        ])
        result = render_report(spec)
        self.assertIn("### Finding 1", result)
        self.assertIn("Some detail", result)

    def test_extra_sections(self):
        spec = ReportSpec(sections=[
            ReportSection("Environment", "| relro | ON |"),
        ])
        result = render_report(spec)
        self.assertIn("## Environment", result)
        self.assertIn("| relro | ON |", result)

    def test_output_files(self):
        spec = ReportSpec(output_files=["findings.json", "report.md"])
        result = render_report(spec)
        self.assertIn("findings.json", result)
        self.assertIn("report.md", result)

    def test_separator_none(self):
        spec = ReportSpec(
            title="Test",
            summary={"A": 1},
            detail_sections=[ReportSection("D1", "content")],
        )
        result = render_report(spec, separator=None)
        # No standalone "---" lines (table alignment rows like |---|---| are fine)
        for line in result.splitlines():
            self.assertNotEqual(line.strip(), "---", f"Found standalone separator: {line!r}")
        self.assertIn("# Test", result)
        self.assertIn("### D1", result)


if __name__ == "__main__":
    unittest.main()
