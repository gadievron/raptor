"""Unit tests for core.security.log_sanitisation."""

import unittest

from core.security.log_sanitisation import (
    _escape_char,
    escape_nonprintable,
    has_nonprintable,
    sanitise_for_terminal,
)


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

    def test_escape_osc8_hyperlink_sequence(self):
        # OSC 8 can turn harmless-looking text into a clickable URL in
        # supporting terminals. Both ESC and BEL must be rendered inert.
        self.assertEqual(
            escape_nonprintable("safe \x1b]8;;https://evil.example\x07click\x1b]8;;\x07"),
            "safe \\x1b]8;;https://evil.example\\x07click\\x1b]8;;\\x07",
        )

    def test_escape_osc52_clipboard_sequence(self):
        # OSC 52 writes to the operator clipboard in some terminals.
        self.assertEqual(
            escape_nonprintable("copy \x1b]52;c;c2VjcmV0\x07 done"),
            "copy \\x1b]52;c;c2VjcmV0\\x07 done",
        )

    def test_escape_dcs_pm_and_apc_sequences(self):
        # DCS, PM, and APC are less common than CSI/OSC but are still
        # terminal control channels and should be neutralised at the ESC byte.
        payload = "\x1bPqdata\x1b\\ \x1b^private\x1b\\ \x1b_app\x1b\\"
        expected = "\\x1bPqdata\\x1b\\ \\x1b^private\\x1b\\ \\x1b_app\\x1b\\"
        self.assertEqual(escape_nonprintable(payload), expected)

    def test_escape_partial_escape_sequence(self):
        # Truncated control sequences are still hostile because a later write
        # could complete them on a live terminal.
        self.assertEqual(
            escape_nonprintable("prefix \x1b]8;;https://evil.example"),
            "prefix \\x1b]8;;https://evil.example",
        )

    def test_escape_very_long_hostile_string(self):
        payload = "A" * 4096 + "\x1b]52;c;c2VjcmV0\x07" + "B" * 4096
        escaped = escape_nonprintable(payload)
        self.assertNotIn("\x1b", escaped)
        self.assertNotIn("\x07", escaped)
        self.assertIn("\\x1b]52;c;c2VjcmV0\\x07", escaped)

    def test_escape_unicode_line_separator(self):
        # U+2028 is a Unicode line separator — some JSON parsers and
        # terminals honour it as a newline. Not printable.
        self.assertEqual(escape_nonprintable("a\u2028b"), "a\\u2028b")

    def test_unicode_printable_passes_through(self):
        # Legitimate non-ASCII content (accented filenames, non-Latin
        # scripts) should not be mangled.
        self.assertEqual(escape_nonprintable("café"), "café")
        self.assertEqual(escape_nonprintable("日本語"), "日本語")

    def test_empty_string(self):
        self.assertEqual(escape_nonprintable(""), "")


class TestPreserveNewlines(unittest.TestCase):
    """`preserve_newlines=True` keeps EXACTLY \\n and \\t; printable text
    passes through untouched and every other control is still escaped."""

    def test_printables_and_structural_whitespace_untouched(self):
        # Both sides of the keep-condition matter: printable chars pass
        # because they are printable (not because they are whitespace),
        # and \n/\t pass because they are structural whitespace (they
        # are NOT printable). A regression in either arm mangles one.
        s = "line one\n\tindented line two\n"
        self.assertEqual(escape_nonprintable(s, preserve_newlines=True), s)

    def test_other_controls_still_escaped_in_preserve_mode(self):
        self.assertEqual(
            escape_nonprintable("a\x1b[31m\nb\r", preserve_newlines=True),
            "a\\x1b[31m\nb\\x0d",
        )

    def test_carriage_return_is_not_structural(self):
        # \r alone re-renders the current line (the log-forgery channel)
        # — only \n and \t are structural.
        self.assertEqual(
            escape_nonprintable("x\ry", preserve_newlines=True), "x\\x0dy",
        )


class TestEscapeCharFormatBoundaries(unittest.TestCase):
    r"""The escape form is chosen by codepoint width: \xHH through
    U+00FF, \uHHHH through U+FFFF, \UHHHHHHHH beyond the BMP. Reviewers
    grep logs for these exact spellings; a shifted boundary silently
    changes the rendered evidence."""

    def test_x_form_ceiling_is_u00ff(self):
        self.assertEqual(_escape_char("\xff"), "\\xff")

    def test_u_form_floor_is_u0100(self):
        self.assertEqual(_escape_char("Ā"), "\\u0100")

    def test_u_form_ceiling_is_uffff(self):
        self.assertEqual(_escape_char("￿"), "\\uffff")

    def test_wide_form_floor_is_u10000(self):
        self.assertEqual(_escape_char("\U00010000"), "\\U00010000")

    def test_astral_nonprintables_escape_via_public_api(self):
        # Astral-plane format characters are REAL attack input: the
        # Unicode tag block (U+E0000..U+E007F, category Cf) is the
        # canonical ASCII-smuggling channel for hiding instructions in
        # text an operator (or a harness LLM) will read. U+FFFF (Cn)
        # and U+10FFFF (Cn) pin both BMP and astral noncharacters.
        self.assertEqual(escape_nonprintable("hi\U000E0041there"),
                         "hi\\U000e0041there")
        self.assertEqual(escape_nonprintable("￿"), "\\uffff")
        self.assertEqual(escape_nonprintable("\U0010FFFF"), "\\U0010ffff")


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

    def test_escape_targets_are_detected(self):
        samples = [
            ("ansi_escape", "A\x1b[31mB"),
            ("null_byte", "pre\x00post"),
            ("crlf", "line1\r\nline2"),
            ("tab", "a\tb"),
            ("delete", "\x7f"),
            ("c1_control", "\x9b[31m"),
            ("osc8_hyperlink", "safe \x1b]8;;https://evil.example\x07click"),
            ("osc52_clipboard", "copy \x1b]52;c;c2VjcmV0\x07 done"),
            ("dcs_pm_apc", "\x1bPqdata\x1b\\ \x1b^private\x1b\\ \x1b_app\x1b\\"),
            ("partial_escape", "prefix \x1b]8;;https://evil.example"),
            ("unicode_line_separator", "a\u2028b"),
        ]
        for name, sample in samples:
            with self.subTest(name=name):
                self.assertTrue(has_nonprintable(sample))

    def test_unicode_printable_false(self):
        self.assertFalse(has_nonprintable("café 日本語"))

    def test_empty_false(self):
        self.assertFalse(has_nonprintable(""))


class SanitiseForTerminalTests(unittest.TestCase):
    def test_escapes_and_passes_short_strings(self):
        self.assertEqual(sanitise_for_terminal("evil\x1b[31m.example"),
                         "evil\\x1b[31m.example")
        self.assertEqual(sanitise_for_terminal("plain.example"),
                         "plain.example")

    def test_truncates_with_explicit_marker(self):
        out = sanitise_for_terminal("a" * 1000, max_len=100)
        self.assertEqual(out, "a" * 100 + "...[+900 chars]")

    def test_truncation_measured_after_escaping(self):
        # Escaping expands each control char to 4 printable chars; the
        # bound applies to what actually reaches the terminal.
        out = sanitise_for_terminal("\x1b" * 1000, max_len=100)
        self.assertLessEqual(len(out), 100 + len("...[+3900 chars]"))
        self.assertNotIn("\x1b", out)

    def test_default_bound_is_256(self):
        # The default cap is part of the operator-facing contract: every
        # call site that omits max_len relies on hostile banners being
        # cut at exactly this point.
        out = sanitise_for_terminal("a" * 300)
        self.assertEqual(out, "a" * 256 + "...[+44 chars]")

    def test_exactly_at_bound_is_not_truncated(self):
        # ==max_len passes untouched — the elision marker only appears
        # when characters were actually dropped (a "+0 chars" marker
        # would be a forged-truncation signal).
        self.assertEqual(sanitise_for_terminal("b" * 256), "b" * 256)
        self.assertEqual(sanitise_for_terminal("b" * 100, max_len=100),
                         "b" * 100)


if __name__ == "__main__":
    unittest.main()
