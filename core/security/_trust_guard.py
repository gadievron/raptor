"""Shared trust-marker guard for ``libexec/`` dispatch scripts.

Centralises the check that was previously inlined (near byte-for-byte) into
~40 ``libexec/`` scripts: an internal dispatch script must be reached through
the ``bin/raptor`` launcher (which exports ``CLAUDECODE`` / ``_RAPTOR_TRUSTED``)
rather than run directly, so a stray ``PATH`` entry or a copy-pasted invocation
can't drive RAPTOR's internals with an unexpected environment.

Deliberately kept dependency-free and in the tiny ``core.security`` package
(an 8-line ``__init__`` with no imports), so importing it costs ~3 ms and still
runs BEFORE any heavy ``core.*`` import - preserving the original
"guard before real work" property the inline block had. Callers must add the
repo root to ``sys.path`` first (the standard
``sys.path.insert(0, str(Path(__file__).resolve().parents[1]))`` line) and then::

    from core.security._trust_guard import require_trusted_caller
    require_trusted_caller()

The genuinely-special shims (``raptor-pid1-shim``, ``raptor-seatbelt-shim``,
and the ``python3 -I`` isolated launchers) keep their inline check - they run
before any ``sys.path`` manipulation by design.
"""

import os
import sys


def require_trusted_caller() -> None:
    """Exit(2) unless invoked via ``bin/raptor`` (CLAUDECODE / _RAPTOR_TRUSTED).

    No-op when trusted; writes the standard guidance to stderr and exits with
    status 2 otherwise (matching the historical inline behaviour)."""
    if os.environ.get("CLAUDECODE") or os.environ.get("_RAPTOR_TRUSTED"):
        return
    sys.stderr.write(
        f"{sys.argv[0]}: internal dispatch script.\n"
        "  Run via 'bin/raptor' instead.\n"
        "  Tests / power users: set _RAPTOR_TRUSTED=1 to bypass.\n"
    )
    sys.exit(2)
