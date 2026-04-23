"""Unit tests for core.security.log_sanitisation."""

import unittest

from core.security.log_sanitisation import escape_nonprintable, has_nonprintable


class TestEscapeNonprintable(unittest.TestCase):
    def test_printable_ascii_unchanged(self):
        s = "Sandbox (landlock+seccomp:full+limits): gcc -c src/main.c"
        self.assertEqual(escape_nonprintable(s), s)

    def test_space_preserved(self):
        # Space is printable per Python's isprintable() — test explicit
        # because callsites (cmd_display) depend on it.
        self.assertEqual(escape_nonprintable("a b c"), "a b c")

    def test_escape_byte_sequence(self):
        # Classic ANSI red on/off: operator-terminal colour-flip attack.
        self.assertEqual(
            escape_nonprintable("A\x1b[31mB\x1b[0mC"),
            "A\\x1b[31mB\\x1b[0mC",
        )

    def test_escape_null_byte(self):
        # NUL isn't printable; also commonly abused to truncate paths.
        self.assertEqual(escape_nonprintable("pre\x00post"), "pre\\x00post")

    def test_escape_crlf(self):
        # Log-line-injection: child prints fake log line terminator to
        # forge a subsequent entry. Must be neutralised.
        self.assertEqual(
            escape_nonprintable("line1\r\nFAKE: all clear"),
            "line1\\x0d\\x0aFAKE: all clear",
        )

    def test_escape_tab(self):
        # Tab is a control char per Python (not isprintable()), escape it.
        self.assertEqual(escape_nonprintable("a\tb"), "a\\x09b")

    def test_escape_del(self):
        self.assertEqual(escape_nonprintable("\x7f"), "\\x7f")

    def test_escape_c1_controls(self):
        # C1 controls (0x80-0x9F) — some terminals honour them. A regex
        # that rejects 0x00-0x1F + 0x7F only would miss these. Confirm
        # isprintable()-based check catches them.
        self.assertEqual(escape_nonprintable("\x9b[31m"), "\\x9b[31m")

    def test_escape_unicode_line_separator(self):
        # U+2028 is a Unicode line separator — some JSON parsers and
        # terminals honour it as a newline. Not printable.
        self.assertEqual(escape_nonprintable("a\u2028b"), "a\\x2028b")

    def test_unicode_printable_passes_through(self):
        # Legitimate non-ASCII content (accented filenames, non-Latin
        # scripts) should not be mangled.
        self.assertEqual(escape_nonprintable("café"), "café")
        self.assertEqual(escape_nonprintable("日本語"), "日本語")

    def test_empty_string(self):
        self.assertEqual(escape_nonprintable(""), "")


class TestHasNonprintable(unittest.TestCase):
    def test_clean_string_false(self):
        self.assertFalse(has_nonprintable("Sandbox: gcc -c src/main.c"))

    def test_with_esc_true(self):
        self.assertTrue(has_nonprintable("evil\x1b[31m"))

    def test_with_null_true(self):
        self.assertTrue(has_nonprintable("pre\x00post"))

    def test_with_crlf_true(self):
        self.assertTrue(has_nonprintable("line1\r\nline2"))

    def test_with_c1_control_true(self):
        self.assertTrue(has_nonprintable("\x9b[31m"))

    def test_unicode_printable_false(self):
        self.assertFalse(has_nonprintable("café 日本語"))

    def test_empty_false(self):
        self.assertFalse(has_nonprintable(""))


if __name__ == "__main__":
    unittest.main()
