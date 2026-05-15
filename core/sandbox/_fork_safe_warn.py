"""Fork-safe post-fork warning emitter for degraded-mode signals.

Uses os.write(2, bytes) which is async-signal-safe — no locks, no
allocation in the syscall path, no Python I/O buffering. Designed for
use inside preexec_fn closures where fork has just occurred and the
process is about to exec or exit. Python's logging machinery and
print() acquire locks that may have been held in the parent at fork
time, so they cannot be called safely from this context.

Two entry points:
- warn_post_fork(category, detail) emits and returns (defense-in-depth)
- fail_post_fork(category, detail, exit_code) emits then os._exit
  (enforcement-path sites that must fail-CLOSED)
"""

import os

_PREFIX = b"RAPTOR: "


def warn_post_fork(category: str, detail: str) -> None:
    """Emit a fork-safe one-line warning to stderr (fd 2).

    Format: ``RAPTOR: <category>: <detail>\\n``.

    OSError is swallowed silently — stderr may be closed or redirected
    in a sandboxed child, and raising would defeat the best-effort
    contract. Callers must not rely on the message being delivered.
    """
    try:
        msg = f"{category}: {detail}".encode("utf-8", errors="replace")
        if not msg.startswith(_PREFIX):
            msg = _PREFIX + msg
        if not msg.endswith(b"\n"):
            msg += b"\n"
        os.write(2, msg)
    except OSError:
        pass


def fail_post_fork(category: str, detail: str, exit_code: int) -> None:
    """Emit a fork-safe warning, then exit the child with exit_code.

    Used at enforcement-path sites where the restriction cannot
    degrade silently. ``os._exit`` skips atexit handlers (which would
    be fork-unsafe) and terminates immediately.
    """
    warn_post_fork(category, detail)
    os._exit(exit_code)
