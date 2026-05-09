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


# Example usage:
if __name__ == "__main__":
    # Test the progress counter
    with HackerProgress(total=10, operation="Analyzing vulnerabilities") as progress:
        for i in range(1, 11):
            time.sleep(2)  # Simulate work
            progress.update(current=i, message=f"vuln_{i}")

    print("\nProgress counter test complete!")
