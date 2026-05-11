"""Regression tests for `core.progress.HackerProgress`."""
from __future__ import annotations

import io
import sys
import unittest
from unittest import mock

from core.progress import (
    HackerProgress,
    HackerProgressBar,
    _stderr_supports_unicode,
)


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


class _FakeTTY(io.StringIO):
    """StringIO that claims to be a TTY for HackerProgressBar's
    auto-disable detection."""

    def isatty(self) -> bool:
        return True


class HackerProgressBarTTYDetectionTest(unittest.TestCase):
    def test_oneline_mode_when_stream_is_not_tty(self) -> None:
        """Plain ``io.StringIO`` reports ``isatty()==False`` —
        bar auto-selects ``oneline`` mode, emitting one line per
        stage with no ANSI clear."""
        buf = io.StringIO()
        with HackerProgressBar(target="x", stream=buf) as bar:
            bar.stage("discovery")
            bar.tick()
            bar.done(summary="3 manifests")
        out = buf.getvalue()
        self.assertNotIn("\x1b[", out)
        self.assertIn("discovery", out)
        self.assertIn("3 manifests", out)

    def test_redraw_mode_when_stream_is_tty(self) -> None:
        """TTY-shaped stream → bar enables redraw; ticks emit
        ANSI clear sequences."""
        buf = _FakeTTY()
        with HackerProgressBar(target="x", stream=buf) as bar:
            bar.stage("osv", total=10)
            for i in range(11):
                bar.tick(done=i)
            bar.done(summary="0 vuln")
        out = buf.getvalue()
        self.assertIn("\x1b[", out)
        self.assertIn("osv", out)


class HackerProgressBarSilentModeTest(unittest.TestCase):
    """``disabled=True`` (operator opt-out via ``--no-progress``)
    must produce zero output. Distinct from non-TTY oneline mode
    which still emits per-stage records suitable for CI logs."""

    def test_disabled_true_emits_nothing(self) -> None:
        buf = io.StringIO()
        with HackerProgressBar(target="repo", disabled=True,
                                stream=buf) as bar:
            bar.stage("discovery")
            bar.tick()
            bar.flash("KEV", "CVE-2021-44228")
            bar.done(summary="120 deps")
            bar.stage("osv", total=10)
            bar.tick(done=5)
            bar.done(summary="14 vuln")
            bar.end(summary="all good")
        # Silent mode: not a single byte hits the stream.
        self.assertEqual(buf.getvalue(), "")

    def test_disabled_true_suppresses_target_header(self) -> None:
        """Even the ``sca > <target>`` prelude is suppressed when
        the operator explicitly opts out."""
        buf = io.StringIO()
        bar = HackerProgressBar(target="repo", disabled=True,
                                  stream=buf)
        del bar
        self.assertEqual(buf.getvalue(), "")


class HackerProgressBarStageLifecycleTest(unittest.TestCase):
    """Lifecycle behaviours — exercise the oneline (non-TTY auto)
    path because it's deterministic to read back from a buffer."""

    def test_oneline_emits_one_line_per_stage(self) -> None:
        buf = io.StringIO()  # not a TTY → auto-selects oneline
        with HackerProgressBar(target="repo", stream=buf) as bar:
            bar.stage("discovery")
            bar.done(summary="120 deps")
            bar.stage("osv")
            bar.done(summary="14 vuln")
            bar.end(summary="all good")
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        # Header + discovery + osv + done footer = 4 lines.
        self.assertEqual(len(lines), 4)
        self.assertIn("sca", lines[0])
        self.assertIn("repo", lines[0])
        self.assertIn("discovery", lines[1])
        self.assertIn("120 deps", lines[1])
        self.assertIn("osv", lines[2])
        self.assertIn("14 vuln", lines[2])
        self.assertIn("done", lines[3])
        self.assertIn("all good", lines[3])

    def test_stage_switch_finalises_prior_stage(self) -> None:
        """Calling ``stage()`` twice without ``done()`` finalises
        the previous one — operator never gets two stages
        appearing simultaneously."""
        buf = io.StringIO()
        with HackerProgressBar(target=None, stream=buf) as bar:
            bar.stage("discovery")
            bar.stage("cascade")  # Implicit finalise of discovery.
            bar.done(summary="ok")
        out = buf.getvalue()
        self.assertIn("discovery", out)
        self.assertIn("cascade", out)

    def test_exit_finalises_in_flight_stage(self) -> None:
        """Context-manager exit cleans up an unfinished stage."""
        buf = io.StringIO()
        with HackerProgressBar(stream=buf) as bar:
            bar.stage("reach")
            bar.tick()
            # No done() call — exit must still emit the line.
        self.assertIn("reach", buf.getvalue())

    def test_exit_with_exception_marks_stage_interrupted(self) -> None:
        """If the body raises, the in-flight stage's final line
        carries ``interrupted`` so the operator sees where it
        died."""
        buf = io.StringIO()
        try:
            with HackerProgressBar(stream=buf) as bar:
                bar.stage("osv")
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        self.assertIn("interrupted", buf.getvalue())


class HackerProgressBarFlashTest(unittest.TestCase):
    def test_flash_emitted_in_tty_mode(self) -> None:
        buf = _FakeTTY()
        with HackerProgressBar(disabled=False, stream=buf) as bar:
            bar.stage("osv", total=100)
            bar.tick(done=10)
            bar.flash("KEV", "CVE-2021-44228 log4j-core@2.14.1")
            bar.tick(done=20)
            bar.done(summary="14 vuln")
        out = buf.getvalue()
        self.assertIn("KEV", out)
        self.assertIn("CVE-2021-44228", out)

    def test_flash_suppressed_in_oneline_mode(self) -> None:
        """Non-TTY oneline mode suppresses flashes — they'd
        interleave oddly with the per-stage one-line output and
        ANSI-less CI logs already get the KEV count from the
        stage detail."""
        buf = io.StringIO()  # non-TTY → oneline
        with HackerProgressBar(stream=buf) as bar:
            bar.stage("osv")
            bar.flash("KEV", "CVE-2021-44228")
            bar.done(summary="ok")
        self.assertNotIn("CVE-2021-44228", buf.getvalue())


class HackerProgressBarTickThrottlingTest(unittest.TestCase):
    def test_tick_advances_internal_counter_even_when_silent(self) -> None:
        """Silent / oneline modes still count ticks for done()'s
        summary, just don't render mid-stage."""
        buf = io.StringIO()
        with HackerProgressBar(disabled=True, stream=buf) as bar:
            bar.stage("x", total=5)
            for _ in range(3):
                bar.tick()
            self.assertEqual(bar._stage_done, 3)


class HackerProgressBarLastStageSideChannelTest(unittest.TestCase):
    """Module-level ``last_stage_name()`` lets out-of-band exception
    handlers report which pipeline phase was active when an error
    occurred — without threading the bar through every call site."""

    def test_stage_call_updates_last_stage_name(self) -> None:
        from core.progress import last_stage_name
        buf = io.StringIO()
        with HackerProgressBar(disabled=True, stream=buf) as bar:
            bar.stage("discovery")
            self.assertEqual(last_stage_name(), "discovery")
            bar.stage("osv")
            self.assertEqual(last_stage_name(), "osv")

    def test_last_stage_persists_after_done(self) -> None:
        """The last-stage value survives ``done()`` / ``end()``
        so handlers can still attribute failures that happen
        between stages (e.g. while writing artefacts after the
        pipeline body returns)."""
        from core.progress import last_stage_name
        buf = io.StringIO()
        with HackerProgressBar(disabled=True, stream=buf) as bar:
            bar.stage("emit")
            bar.done(summary="ok")
            bar.end(summary="all done")
        # End ran; the name should still be retrievable for an
        # exception that fires post-end.
        self.assertEqual(last_stage_name(), "emit")

    def test_silent_bar_still_updates_last_stage(self) -> None:
        """Even when output is suppressed (``--no-progress``),
        the side-channel must still update — operators using
        ``--no-progress`` benefit *more* from a phase-attributed
        error message because they have no rolling stage line to
        glance at."""
        from core.progress import last_stage_name
        buf = io.StringIO()
        with HackerProgressBar(disabled=True, stream=buf) as bar:
            bar.stage("reach")
        self.assertEqual(last_stage_name(), "reach")


if __name__ == "__main__":
    unittest.main()
