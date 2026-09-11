"""Terminal hygiene for untrusted target output."""

from packages.fuzzing.output_hygiene import strip_terminal_controls


class TestStripTerminalControls:
    def test_ansi_escape_neutralised(self):
        # ESC removed leaves the sequence as inert printable text.
        assert strip_terminal_controls("\x1b[31mred\x1b[0m") == "[31mred[0m"

    def test_osc_sequence_neutralised(self):
        out = strip_terminal_controls("\x1b]0;owned\x07title")
        assert "\x1b" not in out
        assert "\x07" not in out

    def test_c1_controls_removed(self):
        assert strip_terminal_controls("a\x9b31mb") == "a31mb"

    def test_carriage_return_removed(self):
        # \r enables line-rewriting forgery in scrollback.
        assert strip_terminal_controls("ok\rall clean") == "okall clean"

    def test_newline_and_tab_preserved(self):
        assert strip_terminal_controls("a\nb\tc") == "a\nb\tc"

    def test_plain_text_untouched(self):
        text = "exec/s: 1234 (100.0%) paths: 7"
        assert strip_terminal_controls(text) == text
