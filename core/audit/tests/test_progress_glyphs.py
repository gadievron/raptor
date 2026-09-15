"""Progress-line rendering for the /audit operator stream."""

from __future__ import annotations

from core.audit._util import STATUS_GLYPHS, format_progress_line
from core.audit.orchestrator import ReviewOutcome


def _outcome(status: str, body: str = "reviewed") -> ReviewOutcome:
    return ReviewOutcome(
        file="src/auth.c", function="check_pw", status=status, body=body,
    )


class TestStatusGlyphs:
    def test_coherent_set(self):
        # OUTPUT STYLE: ✓/✗ fine, no red/green circles; the old bare
        # "x" for error read as noise next to the status word.
        assert STATUS_GLYPHS == {
            "clean": "✓",
            "suspicious": "?",
            "finding": "!",
            "dormant": "~",
            "error": "✗",
        }
        assert "🔴" not in STATUS_GLYPHS.values()
        assert "🟢" not in STATUS_GLYPHS.values()

    def test_error_line_uses_failure_glyph(self):
        line = format_progress_line(5, 15, _outcome("error"))
        assert line == "  [6/15] src/auth.c:check_pw → error ✗"
        assert not line.endswith(" x")

    def test_clean_line(self):
        line = format_progress_line(0, 15, _outcome("clean"))
        assert line == "  [1/15] src/auth.c:check_pw → clean ✓"

    def test_every_journal_status_renders(self):
        for status, glyph in STATUS_GLYPHS.items():
            line = format_progress_line(2, 9, _outcome(status))
            assert line.endswith(f"→ {status} {glyph}")

    def test_unknown_status_gets_neutral_glyph(self):
        line = format_progress_line(0, 1, _outcome("dark"))
        assert line.endswith("→ dark ·")

    def test_negative_idx_prints_body_verbatim(self):
        # Loop-level announcement channel (budget-exhaustion stop line).
        msg = ("budget exhausted after 5/15 reviews — stopping; 10 "
               "functions left unreviewed (they remain gaps for a "
               "future run)")
        line = format_progress_line(-1, 15, _outcome("error", body=msg))
        assert line == f"  {msg}"


class TestHostileFieldsEscaped:
    """file/function/body are foreign-derived (scanned-repo names, tool
    output); ESC/OSC/BEL/bidi bytes in them must never reach the
    operator's terminal raw."""

    HOSTILE = "\x1b]0;pwned\x07\x1b[2J\x9b1m‮evil"

    def test_hostile_file_and_function_escaped(self):
        outcome = ReviewOutcome(
            file=f"src/{self.HOSTILE}.c",
            function=f"fn{self.HOSTILE}",
            status="clean", body="",
        )
        line = format_progress_line(0, 3, outcome)
        for raw in ("\x1b", "\x07", "\x9b", "‮"):
            assert raw not in line
        # RAPTOR's own framing survives untouched.
        assert line.startswith("  [1/3] ")
        assert line.endswith("→ clean ✓")

    def test_hostile_body_escaped_on_verbatim_channel(self):
        outcome = _outcome("error", body=f"joern: {self.HOSTILE} done")
        line = format_progress_line(-1, 3, outcome)
        for raw in ("\x1b", "\x07", "\x9b", "‮"):
            assert raw not in line
        assert "joern:" in line

    def test_hostile_status_escaped(self):
        outcome = _outcome(self.HOSTILE)
        line = format_progress_line(0, 3, outcome)
        assert "\x1b" not in line and "\x07" not in line

    def test_oversized_field_bounded(self):
        # A hostile 100 KB "file name" must not flood the terminal.
        outcome = ReviewOutcome(
            file="a" * 100_000, function="f", status="clean", body="",
        )
        line = format_progress_line(0, 3, outcome)
        assert len(line) < 1_000
        assert "chars]" in line
