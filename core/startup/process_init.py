"""Common process-level initialisation for RAPTOR scripts.

Importing this module enables:

- ``faulthandler``: dumps all thread stacks on SIGUSR1 (Linux/macOS)
  and on fatal signals (SIGSEGV, SIGBUS, SIGABRT, SIGFPE). Only when
  ``sys.stderr`` has a real file descriptor — under a captured /
  in-memory stderr (e.g. some test harnesses), ``init()`` silently
  does nothing.
- Future: structured logging setup, locale normalisation, etc.

Usage in libexec scripts (one import, no function call needed)::

    import core.startup.process_init  # noqa: F401,E402
"""

from __future__ import annotations

import faulthandler
import importlib.util
import io
import os
import signal
import sys

# Run before dependency discovery: writable search paths must not satisfy
# the protected helper's package checks. This does not cover startup hooks
# that ran before this file; isolated entry points close that earlier route.
if os.environ.get("RAPTOR_INSTALL_PROTECTED") == "1":
    try:
        from core.security.python_imports import harden_import_paths
        harden_import_paths()
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        raise SystemExit("RAPTOR: protected Python import paths could not be established; "
                         "restart through bin/raptor --protect-install") from exc


if (
    not os.environ.get("CI")
    and not os.environ.get("RAPTOR_CI")
    and os.environ.get("_RAPTOR_DEP_CHECK", "1") != "0"
):
    _REQUIRED_DEPS = ("requests", "pydantic", "openai", "yaml")
    _missing = [m for m in _REQUIRED_DEPS if importlib.util.find_spec(m) is None]
    if _missing:
        _in_venv = sys.prefix != sys.base_prefix
        _hint = "uv sync --locked" if _in_venv else "source .venv/bin/activate"
        sys.stderr.write(
            f"raptor: missing dependencies: {', '.join(_missing)}\n"
            f"  run: {_hint}\n"
            f"  interpreter: {sys.executable}\n"
        )
        raise SystemExit(1)
    del _missing, _REQUIRED_DEPS


def _stderr_has_fileno() -> bool:
    try:
        sys.stderr.fileno()
        return True
    except (OSError, io.UnsupportedOperation):
        return False


def init() -> None:
    """One-shot process bootstrap — safe to call multiple times."""
    from core.security.launch_scratch import restore
    try:
        restore()
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        raise SystemExit('RAPTOR: temporary directory or launch metadata unavailable or invalid; '
                         'check TMPDIR and restart launcher sessions through bin/raptor') from exc
    if not _stderr_has_fileno():
        return
    faulthandler.enable()
    if hasattr(signal, "SIGUSR1"):
        faulthandler.register(signal.SIGUSR1, all_threads=True, file=sys.stderr)


init()
