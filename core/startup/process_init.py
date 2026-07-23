"""Common process-level initialisation for RAPTOR scripts.

Importing this module enables:

- ``faulthandler``: dumps all thread stacks on SIGUSR1 (Linux/macOS)
  and on fatal signals (SIGSEGV, SIGBUS, SIGABRT, SIGFPE).
- Future: structured logging setup, locale normalisation, etc.

Usage in libexec scripts (one import, no function call needed)::

    import core.startup.process_init  # noqa: F401,E402
"""

from __future__ import annotations

import faulthandler
import io
import signal
import sys


def _stderr_has_fileno() -> bool:
    try:
        sys.stderr.fileno()
        return True
    except (OSError, io.UnsupportedOperation):
        return False


def init() -> None:
    """One-shot process bootstrap — safe to call multiple times."""
    if not _stderr_has_fileno():
        return
    faulthandler.enable()
    if hasattr(signal, "SIGUSR1"):
        faulthandler.register(signal.SIGUSR1, all_threads=True, file=sys.stderr)


init()
