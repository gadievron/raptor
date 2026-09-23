#!/usr/bin/env python3
"""Tests for console table rendering."""

import unittest
from core.reporting.console import render_console_table


class TestRenderConsoleTable(unittest.TestCase):

    def test_basic_table(self):
        result = render_console_table(
            columns=["#", "Name", "Status"],
            rows=[("1", "foo", "OK"), ("2", "bar", "FAIL")],
        )
        self.assertIn("┌", result)
        self.assertIn("┘", result)
        self.assertIn("foo", result)
        self.assertIn("FAIL", result)

    def test_title(self):
        result = render_console_table(
            columns=["A"], rows=[("x",)], title="My Table",
        )
        self.assertIn("My Table", result)

    def test_footer(self):
        result = render_console_table(
            columns=["A"], rows=[("x",)], footer="Done.",
        )
        self.assertIn("Done.", result)

    def test_max_widths(self):
        result = render_console_table(
            columns=["Name"],
            rows=[("a" * 100,)],
            max_widths={0: 10},
        )
        # Row should be truncated
        self.assertNotIn("a" * 100, result)

    def test_empty_rows(self):
        result = render_console_table(columns=["A", "B"], rows=[])
        self.assertIn("┌", result)
        self.assertIn("┘", result)

    def test_hostile_title_and_footer_escaped(self):
        # Cells and headers were already escaped; the title and footer
        # reach the terminal through the same return value and carry
        # finding-influenceable text, so raw ANSI/BEL must not survive
        # in them either.
        result = render_console_table(
            columns=["A"], rows=[("x",)],
            title="EVIL\x1b[2J\x07TITLE",
            footer="F\x1b]0;pwned\x07OOT",
        )
        self.assertNotIn("\x1b", result)
        self.assertNotIn("\x07", result)
        self.assertIn("TITLE", result)
        self.assertIn("OOT", result)

    def test_zero_width_flood_bounded_under_cap(self):
        # Combining marks are printable (escaping keeps them) and zero
        # display columns wide: a capped column's width check never
        # trips, so only a code-point ceiling bounds the cell. The
        # flood must come back cut, not whole.
        flood = "a" + "̀" * 8000
        result = render_console_table(
            columns=["F"], rows=[(flood,)], max_widths={0: 10},
        )
        longest = max(len(line) for line in result.splitlines())
        self.assertLess(longest, 200)

    def test_uncapped_column_gets_default_ceiling(self):
        # Columns without an explicit cap no longer size to their
        # longest cell unbounded — one hostile cell must not dictate
        # every row's width.
        result = render_console_table(
            columns=["Type"], rows=[("x" * 100_000,)],
        )
        longest = max(len(line) for line in result.splitlines())
        self.assertLess(longest, 300)

    def test_explicit_cap_above_default_wins(self):
        # An explicit caller cap is authoritative in both directions.
        wide = "w" * 400
        result = render_console_table(
            columns=["C"], rows=[(wide,)], max_widths={0: 500},
        )
        self.assertIn(wide, result)

    def test_hostile_title_and_footer_bounded(self):
        # Escaping alone does not bound LENGTH — a flooded title or
        # footer must be elided, not passed through whole.
        result = render_console_table(
            columns=["A"], rows=[("x",)],
            title="T" * 1_000_000, footer="F" * 1_000_000,
        )
        self.assertLess(len(result), 20_000)
        self.assertIn("[elided]", result)

    def test_large_table_renders_in_linear_time(self):
        # The truncation walk is O(cell length) per cell; the old
        # per-character width-of-prefix recomputation was O(N²) and
        # took ~14 s at a single 100k-char cell. Generous wall pin —
        # an order of magnitude of headroom over observed fixed-code
        # timings (< 0.2 s) while staying far below the quadratic
        # regression's cost.
        import time
        cell = "b" * 100_000
        start = time.monotonic()
        render_console_table(columns=["A"], rows=[(cell,)])
        self.assertLess(time.monotonic() - start, 5.0)


if __name__ == "__main__":
    unittest.main()
