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
import signal
import sys


def init() -> None:
    """One-shot process bootstrap — safe to call multiple times."""
    faulthandler.enable()
    if hasattr(signal, "SIGUSR1"):
        faulthandler.register(signal.SIGUSR1, all_threads=True, file=sys.stderr)


init()
