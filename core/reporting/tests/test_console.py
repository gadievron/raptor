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


if __name__ == "__main__":
    unittest.main()
