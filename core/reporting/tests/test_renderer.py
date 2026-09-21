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
        # Markup belongs to the TEMPLATE, never to the value:
        # sanitise_inline entity-escapes in-value backticks/pipes, so a
        # caller-authored `...` wrapper inside a metadata VALUE renders
        # as entities. Values are plain text.
        spec = ReportSpec(
            title="Report",
            metadata={"Target": "/tmp/test", "Date": "2026-04-04"},
        )
        result = render_report(spec)
        self.assertIn("**Target:** /tmp/test", result)
        self.assertIn("**Date:** 2026-04-04", result)

    def test_metadata_value_cannot_carry_live_span_markup(self):
        # The structure-escape direction: a hostile value cannot open
        # or close inline-code spans / split cells in the rendered
        # report — the raw delimiters never survive.
        spec = ReportSpec(
            title="Report",
            metadata={"Target": "`x` | pwned"},
        )
        result = render_report(spec)
        self.assertNotIn("`", result.split("\n")[2])
        self.assertIn("&#96;x&#96; &#124; pwned", result)

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


class TestRendererDefangsSingleLineSlots(unittest.TestCase):
    """The renderer is a shared chokepoint: a NEW render_report caller
    that skips producer-side sanitisation must not be able to leak
    heading forgery, autofetch markup, or control bytes through the
    single-line slots — while producer-built markdown in section
    content keeps its structure (control bytes only are escaped)."""

    HOSTILE = "\x1b]0;pwned\x07\x9b2J‮evil"

    def test_hostile_title_metadata_cells_escaped(self):
        spec = ReportSpec(
            title=f"Report {self.HOSTILE}\n# forged",
            metadata={f"k{self.HOSTILE}": f"v{self.HOSTILE}"},
            summary={f"s{self.HOSTILE}": f"val|{self.HOSTILE}"},
            warnings=[f"warn {self.HOSTILE}"],
            table_columns=["#", f"Name{self.HOSTILE}"],
            table_rows=[(f"a|b{self.HOSTILE}", "<img src=//evil.example/x>")],
        )
        out = render_report(spec)
        for raw in ("\x1b", "\x07", "\x9b", "‮"):
            self.assertNotIn(raw, out)
        # A newline in the title cannot start a forged heading line.
        self.assertNotIn("\n# forged", out)
        # Autofetch markup in a cell is stripped.
        self.assertNotIn("//evil.example", out)
        # A bare pipe in a cell cannot terminate its row: the hostile
        # row still renders with the expected column count.
        row_line = next(line for line in out.splitlines()
                        if line.startswith("| a"))
        self.assertEqual(row_line.count(" | "), 1)
        # Legitimate label text survives (the '#' column header).
        self.assertIn("| # |", out)

    def test_section_content_structure_preserved_controls_escaped(self):
        content = f"## producer heading\n\n- item\n\nrow {self.HOSTILE}"
        spec = ReportSpec(
            title="T",
            sections=[ReportSection("Env", content)],
        )
        out = render_report(spec)
        self.assertIn("## producer heading", out)
        self.assertIn("- item", out)
        for raw in ("\x1b", "\x07", "\x9b", "‮"):
            self.assertNotIn(raw, out)

    def test_hostile_section_title_cannot_escape_heading(self):
        spec = ReportSpec(
            title="T",
            sections=[ReportSection(f"S\ninjected {self.HOSTILE}", "c")],
        )
        out = render_report(spec)
        self.assertNotIn("\ninjected", out)
        self.assertNotIn("\x1b", out)
