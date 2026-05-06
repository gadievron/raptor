"""Regression tests for `core.progress.HackerProgress`."""
from __future__ import annotations

import io
import sys
import unittest
from unittest import mock

from core.progress import HackerProgress, _stderr_supports_unicode


class CalculateETATest(unittest.TestCase):
    def test_overrun_clamps_to_zero(self) -> None:
        """ETA never goes negative even when current > total."""
        p = HackerProgress(total=10, operation="t")
        # Force a non-zero rate so the multiplication actually
        # produces a negative number — without this `rate` would
        # be 0 and the bug doesn't trigger.
        p.start_time = p.start_time - 1.0
        p.current = 50  # Overrun by 5x.
        self.assertEqual(p._calculate_eta(), "0s")

    def test_normal_eta_unaffected(self) -> None:
        p = HackerProgress(total=10, operation="t")
        p.start_time = p.start_time - 1.0
        p.current = 5
        self.assertNotEqual(p._calculate_eta(), "calculating...")
        self.assertNotEqual(p._calculate_eta(), "0s")


class ClearEOLTest(unittest.TestCase):
    def test_status_line_includes_clear_eol(self) -> None:
        """Each status line carries `\\033[K` after the carriage
        return so longer prior lines don't bleed through."""
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            p = HackerProgress(total=5, operation="t")
            p.start_time = p.start_time - 5.0  # Get past throttle.
            p.last_update = 0
            p.update(current=1)
            self.assertIn("\r\x1b[K", err.getvalue())


class ExitMessageTest(unittest.TestCase):
    def test_exit_with_exception_includes_repr(self) -> None:
        """__exit__ message includes the exception repr so the
        operator can see WHICH error aborted the operation."""
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            try:
                with HackerProgress(operation="t"):
                    raise ValueError("specific-marker")
            except ValueError:
                pass
            self.assertIn("specific-marker", err.getvalue())
            self.assertIn("ValueError", err.getvalue())

    def test_exit_clean_emits_check(self) -> None:
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            with HackerProgress(operation="t"):
                pass
            # ASCII fallback ([OK]) or unicode (✓) — both acceptable.
            output = err.getvalue()
            self.assertTrue(
                "✓" in output or "[OK]" in output,
                f"finish marker missing in: {output!r}",
            )


class UnicodeProbeTest(unittest.TestCase):
    def test_probe_handles_missing_encoding_attr(self) -> None:
        """Probe returns False if stderr lacks an `encoding`
        attribute — pre-fix this raised AttributeError on import."""
        fake = mock.MagicMock(spec=[])  # No `encoding`.
        with mock.patch.object(sys, "stderr", fake):
            self.assertFalse(_stderr_supports_unicode())


if __name__ == "__main__":
    unittest.main()
