"""
RAPTOR Progress Counter - Matrix/Hacker Style
For operations that take >15 seconds.
"""

import sys
import time
from datetime import datetime
from typing import Optional


class HackerProgress:
    """Matrix-style progress counter for long operations."""

    SPINNERS = ['▌', '▀', '▐', '▄']  # Block rotation

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
        return self._format_time(remaining)

    def update(self, current: Optional[int] = None, message: str = ""):
        """Update progress display."""
        if self.disabled:
            return
        now = time.time()

        # Only update display every 1 second
        if now - self.last_update < 1.0:
            return

        self.last_update = now

        if current is not None:
            self.current = current
        else:
            self.current += 1

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

        # Overwrite previous line
        sys.stderr.write(f"\r{status}")
        sys.stderr.flush()

    def finish(self, message: str = "Complete"):
        """Finish progress and move to new line."""
        elapsed = self._format_time(time.time() - self.start_time)
        sys.stderr.write(f"\r✓ {message} ({elapsed})\n")
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
            sys.stderr.write(f"\r✗ {self.operation} failed\n")
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
