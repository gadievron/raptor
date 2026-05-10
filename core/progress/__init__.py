"""
RAPTOR Progress Counter - Matrix/Hacker Style
For operations that take >15 seconds.
"""

import locale
import sys
import time
from datetime import datetime
from typing import Optional


def _stderr_supports_unicode() -> bool:
    """Probe whether stderr can encode the unicode block characters
    used by the spinner / status decorations.

    Returns False under POSIX/C locale, on legacy 7-bit terminals,
    and on platforms where stderr lacks an `encoding` attribute.
    Pre-fix every write to stderr risked
    `UnicodeEncodeError: 'ascii' codec can't encode character '\\u2588'`
    when the operator's locale was `C` (common in containers and
    minimal CI runners), aborting the entire `with HackerProgress`
    block partway through. Detect once at import.
    """
    enc = getattr(sys.stderr, "encoding", None)
    if not enc:
        return False
    try:
        "▌▀▐▄✓✗".encode(enc)
    except (UnicodeEncodeError, LookupError):
        return False
    # Also check the locale's stated encoding — some terminals
    # advertise utf-8 on the file object but the wrapping pipe
    # is C/POSIX and downgrades.
    try:
        loc = locale.getpreferredencoding(False)
        if loc and loc.lower() in {"ascii", "ansi_x3.4-1968", "us-ascii"}:
            return False
    except locale.Error:
        return False
    return True


_UNICODE_OK = _stderr_supports_unicode()


class HackerProgress:
    """Matrix-style progress counter for long operations."""

    # Spinner glyphs picked at import time based on stderr encoding.
    # ASCII fallback uses 4 rotating chars so the visual cadence
    # still reads as an animation under POSIX locales.
    SPINNERS = ['▌', '▀', '▐', '▄'] if _UNICODE_OK else ['|', '/', '-', '\\']
    _CHECK = '✓' if _UNICODE_OK else '[OK]'
    _CROSS = '✗' if _UNICODE_OK else '[FAIL]'

    def __init__(self, total: Optional[int] = None, operation: str = "Processing",
                 disabled: bool = False):
        self.total = total
        self.operation = operation
        self.disabled = disabled
        self.current = 0
        self.start_time = time.time()
        self.last_update = 0
        self.spinner_idx = 0

    def _format_time(self, seconds: float) -> str:
        """Format seconds as Xm Ys or Xs."""
        if seconds < 60:
            return f"{int(seconds)}s"
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"

    def _calculate_eta(self) -> str:
        """Calculate estimated time remaining."""
        if not self.total or self.current == 0:
            return "calculating..."

        elapsed = time.time() - self.start_time
        rate = elapsed / self.current
        remaining = (self.total - self.current) * rate
        # Clamp to >=0. When the caller-driven loop overruns the
        # initially-declared total (work expanded mid-run, total
        # was an underestimate), `current > total` makes
        # `remaining` negative, and `_format_time(-30)` emits
        # `-30s` which then renders as `ETA: -30s`. Operators
        # interpret that as a bug (or a clock skew). Showing
        # `0s` for an overrun is the honest reading: we already
        # passed the projected total.
        if remaining < 0:
            remaining = 0
        return self._format_time(remaining)

    def update(self, current: Optional[int] = None, message: str = ""):
        """Update progress display."""
        if self.disabled:
            return
        now = time.time()

        # Update self.current ALWAYS — only the I/O is throttled. Otherwise
        # rapid `update(current=idx)` calls in a tight loop silently drop
        # values, leaving the displayed counter and ETA arithmetic stale.
        if current is not None:
            self.current = current
        else:
            self.current += 1

        # Only update display every 1 second.
        if now - self.last_update < 1.0:
            return

        self.last_update = now

        # Rotate spinner
        spinner = self.SPINNERS[self.spinner_idx % len(self.SPINNERS)]
        self.spinner_idx += 1

        # Build status line
        timestamp = datetime.now().strftime("%H:%M:%S")
        elapsed = self._format_time(now - self.start_time)

        if self.total:
            progress = f"{self.current}/{self.total}"
            eta = self._calculate_eta()
            status = f"[{timestamp}] {spinner} {self.operation} {progress} | Elapsed: {elapsed} | ETA: {eta}"
        else:
            status = f"[{timestamp}] {spinner} {self.operation} | Elapsed: {elapsed}"

        if message:
            status += f" | {message}"

        # Overwrite previous line. `\033[K` clears from the cursor
        # to end-of-line AFTER the carriage return — without it,
        # if the previous status line was longer than the current
        # one (e.g. earlier message was a long fid like
        # `vuln_12345_long_finding_id`, current is just `vuln_1`),
        # residual chars from the old line stay visible past the
        # end of the new one. Operators see a corrupted-looking
        # status: `vuln_1nding_id`. The clear-EOL escape removes
        # the leftover tail. No-op on terminals that don't support
        # ANSI (printed as a literal sequence at worst, which is
        # already what HackerProgress assumes for the spinner).
        sys.stderr.write(f"\r\033[K{status}")
        sys.stderr.flush()

    def finish(self, message: str = "Complete"):
        """Finish progress and move to new line."""
        elapsed = self._format_time(time.time() - self.start_time)
        sys.stderr.write(f"\r\033[K{self._CHECK} {message} ({elapsed})\n")
        sys.stderr.flush()

    def __enter__(self):
        """Context manager entry."""
        if not self.disabled:
            sys.stderr.write(f">>> {self.operation.upper()} SEQUENCE ACTIVE <<<\n")
            sys.stderr.flush()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.disabled:
            return False
        if exc_type is None:
            self.finish()
        else:
            # Include the exception's repr so the operator sees
            # WHICH exception aborted the operation. Pre-fix the
            # message was just "{operation} failed" — when a
            # 30-minute scan died you saw "Analyzing vulnerabilities
            # failed" with no clue whether it was a timeout, a 401,
            # or a KeyboardInterrupt. The traceback lands further
            # up in stderr but is easy to miss when the progress
            # output is the last visible thing.
            try:
                exc_repr = repr(exc_val) if exc_val is not None else exc_type.__name__
            except Exception:
                exc_repr = "<unrepresentable exception>"
            sys.stderr.write(
                f"\r\033[K{self._CROSS} {self.operation} failed: {exc_repr}\n"
            )
            sys.stderr.flush()
        return False


class HackerProgressBar:
    """Multi-stage progress display for SCA-shaped pipelines.

    Each stage gets a single self-rewriting line (cleared + reprinted
    on each tick) showing the active stage name, an optional progress
    bar, and a counter. When the stage completes, the line is
    rewritten one final time to the stage's summary form and a
    newline locks it in scrollback. The next ``stage()`` call begins
    a fresh self-rewriting line below.

    Finding-flash callouts (``flash()``) interleave: the active line
    is cleared, the flash line is printed and locked, then the
    active line is re-rendered below. The flash sticks in scrollback;
    the active line continues advancing.

    TTY-only by default (``disabled`` auto-set when stderr isn't a
    TTY). Non-TTY path emits one start-line and one done-line per
    stage with no redraws — friendly to pipes / CI logs / file
    redirects.

    Single-stage pipelines should use ``HackerProgress`` (above) —
    that's the simpler operations >15s case. ``HackerProgressBar``
    is for pipelines with N discrete phases the operator wants
    to see resolve one by one.
    """

    _BLOCK_FULL = "▓" if _UNICODE_OK else "#"
    _BLOCK_EMPTY = "░" if _UNICODE_OK else "."
    _STAGE_GLYPH = "·"
    _DONE_GLYPH = "✓" if _UNICODE_OK else "[OK]"
    _FLASH_GLYPH = "↳" if _UNICODE_OK else "->"

    def __init__(self, *, target: Optional[str] = None,
                 disabled: Optional[bool] = None,
                 stream=None,
                 bar_width: int = 12):
        self._stream = stream if stream is not None else sys.stderr
        # Three modes:
        #   "redraw"  — TTY: rewriting stage lines + flashes + ANSI
        #   "oneline" — non-TTY: one finalised line per stage, no
        #               ANSI, no flashes (CI logs / pipes / file
        #               redirect)
        #   "silent"  — operator opted out via disabled=True
        if disabled is True:
            self._mode = "silent"
        elif disabled is False:
            self._mode = "redraw"
        else:
            is_tty = getattr(self._stream, "isatty",
                              lambda: False)()
            self._mode = "redraw" if is_tty else "oneline"
        # Back-compat: existing code paths read self._disabled to
        # mean "anything but the rich redraw form" — both ``silent``
        # and ``oneline`` skip ANSI / per-tick redraws / flashes.
        # The fine-grained ``self._mode`` discriminates between
        # them where it matters.
        self._disabled = self._mode != "redraw"
        self._target = str(target) if target is not None else None
        self._bar_width = bar_width
        # Per-stage state
        self._stage: Optional[str] = None
        self._stage_total: Optional[int] = None
        self._stage_done: int = 0
        self._stage_start: float = 0.0
        self._stage_detail: str = ""
        # Throttling — max ~10 Hz
        self._last_redraw: float = 0.0
        # Set when an active line is currently drawn and must be
        # cleared before any new write to this stream.
        self._line_active: bool = False
        self._t0 = time.time()
        # Header is emitted at construction so callers don't have to
        # use ``with`` to get it — the SCA pipeline wires this in
        # without re-indenting its 460-line body. The context-
        # manager protocol still works for callers that want
        # exception-safe finalisation. Suppressed in silent mode
        # (operator opt-out) but emitted in oneline mode (CI logs
        # benefit from the target prelude).
        if self._mode != "silent" and self._target:
            self._stream.write(f"sca > {self._target}\n")
            self._stream.flush()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Finalise any in-flight stage so the operator sees its
        # detail rather than the bar.
        if self._stage is not None:
            self._finalise_stage(detail="interrupted"
                                  if exc_type else self._stage_detail)
        return False

    def stage(self, name: str, total: Optional[int] = None) -> None:
        """Begin a new stage. Finalises any prior in-flight stage."""
        if self._stage is not None:
            self._finalise_stage(detail=self._stage_detail)
        self._stage = name
        self._stage_total = total
        self._stage_done = 0
        self._stage_start = time.time()
        self._stage_detail = ""
        self._last_redraw = 0.0
        self._render()

    def tick(self, done: Optional[int] = None,
             detail: str = "") -> None:
        """Advance progress within the current stage. Throttled."""
        if self._stage is None:
            return
        if done is not None:
            self._stage_done = done
        else:
            self._stage_done += 1
        if detail:
            self._stage_detail = detail
        if self._disabled:
            return
        now = time.time()
        if now - self._last_redraw < 0.1:
            return
        self._last_redraw = now
        self._render()

    def flash(self, severity: str, message: str) -> None:
        """Emit a callout above the active stage line."""
        if self._disabled:
            return
        # Clear the active line, write the flash, leave a newline,
        # then re-render the active stage line below.
        self._clear_active_line()
        sev = severity.upper()[:5]
        self._stream.write(
            f"      {self._FLASH_GLYPH} {sev:5s} {message}\n"
        )
        self._stream.flush()
        self._render()

    def done(self, summary: str = "") -> None:
        """Finalise the current stage with a summary detail."""
        if self._stage is None:
            return
        self._finalise_stage(detail=summary or self._stage_detail)

    def end(self, summary: str = "") -> None:
        """End all progress; print final summary footer."""
        if self._stage is not None:
            self._finalise_stage(detail=self._stage_detail)
        if self._mode == "silent":
            return
        elapsed = time.time() - self._t0
        mins = int(elapsed // 60)
        secs = elapsed - mins * 60
        elapsed_str = (f"{mins}m {secs:.0f}s" if mins
                       else f"{secs:.1f}s")
        self._stream.write(
            f"  {self._DONE_GLYPH} done · {elapsed_str}"
            + (f" · {summary}" if summary else "")
            + "\n"
        )
        self._stream.flush()

    # ----- internals -----

    def _finalise_stage(self, *, detail: str) -> None:
        if self._mode == "silent":
            self._stage = None
            return
        if self._mode == "oneline":
            # Non-TTY: emit a single line with the final detail.
            self._stream.write(
                f"  {self._STAGE_GLYPH} {self._stage:<12s} "
                f"{detail or '...'}\n"
            )
            self._stream.flush()
        else:
            self._clear_active_line()
            line = self._format_line(final=True, detail=detail)
            self._stream.write(line + "\n")
            self._stream.flush()
        self._stage = None

    def _render(self) -> None:
        if self._disabled or self._stage is None:
            return
        self._clear_active_line()
        self._stream.write(self._format_line(final=False))
        self._stream.flush()
        self._line_active = True

    def _format_line(self, *, final: bool,
                     detail: Optional[str] = None) -> str:
        name = self._stage or ""
        if final:
            text = detail or "..."
            return f"  {self._STAGE_GLYPH} {name:<12s} {text}"
        if self._stage_total:
            ratio = max(0.0, min(1.0, self._stage_done / self._stage_total))
            filled = int(ratio * self._bar_width)
            bar = (self._BLOCK_FULL * filled
                   + self._BLOCK_EMPTY * (self._bar_width - filled))
            return (
                f"  {self._STAGE_GLYPH} {name:<12s} "
                f"[{bar}] {self._stage_done}/{self._stage_total} "
                f"({ratio*100:.0f}%)"
                + (f" · {self._stage_detail}"
                    if self._stage_detail else "")
            )
        # Indeterminate stage — just dots + detail.
        return (
            f"  {self._STAGE_GLYPH} {name:<12s} ..."
            + (f" {self._stage_detail}" if self._stage_detail else "")
        )

    def _clear_active_line(self) -> None:
        if self._line_active:
            self._stream.write("\r\033[K")
            self._line_active = False


# Example usage:
if __name__ == "__main__":
    # Test the progress counter
    with HackerProgress(total=10, operation="Analyzing vulnerabilities") as progress:
        for i in range(1, 11):
            time.sleep(2)  # Simulate work
            progress.update(current=i, message=f"vuln_{i}")

    print("\nProgress counter test complete!")
