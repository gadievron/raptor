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
