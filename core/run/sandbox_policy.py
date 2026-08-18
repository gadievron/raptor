"""Fail-closed policy for "sandbox unavailable" at tool-runner seams.

Several packages construct a subprocess-runner around
``core.sandbox.run`` at call time (``from core.sandbox import run``
inside a factory). Pre-fix, an ImportError there silently degraded to
bare ``subprocess.run`` — the try-import-sandbox-except-bare-subprocess
shape: the operator asked for an isolated scan of untrusted input and
got an unisolated one with no signal.

This module is the single policy point for that seam. It deliberately
does NOT import ``core.sandbox`` (it is consulted precisely when that
import failed) and has no dependencies beyond stdlib +
``core.logging``.

Semantics:

  - Default: raise :class:`SandboxUnavailableError` naming the remedy.
    The tool does not run.
  - Explicit opt-in (``RAPTOR_ALLOW_UNSANDBOXED_TOOLS=1``): return,
    letting the caller fall back to bare ``subprocess.run`` — with a
    loud operator-visible warning and a security-event emission so the
    audit trail records that isolation was waived. Intended for
    dev hosts where ``core.sandbox``'s platform prerequisites are
    genuinely absent and the input is trusted.
"""

from __future__ import annotations

import logging
import os

from core.logging import log_security_event

logger = logging.getLogger(__name__)

__all__ = [
    "ALLOW_UNSANDBOXED_ENV",
    "SandboxUnavailableError",
    "require_sandbox_or_optout",
]

ALLOW_UNSANDBOXED_ENV = "RAPTOR_ALLOW_UNSANDBOXED_TOOLS"


class SandboxUnavailableError(RuntimeError):
    """core.sandbox could not be imported and the operator has not
    opted into unsandboxed execution."""


def unsandboxed_optout_active() -> bool:
    """Whether the operator has explicitly waived sandbox isolation."""
    return os.environ.get(ALLOW_UNSANDBOXED_ENV) == "1"


def require_sandbox_or_optout(tool: str, exc: BaseException | None) -> None:
    """Decide the fallback when ``from core.sandbox import ...`` failed.

    Args:
        tool: human-readable name of the runner seam (appears in the
            error, the warning, and the security event).
        exc: the import failure, chained into the raised error.

    Raises:
        SandboxUnavailableError: always, unless the
            ``RAPTOR_ALLOW_UNSANDBOXED_TOOLS=1`` opt-in is set — in
            which case a loud warning + ``unsandboxed_tool_fallback``
            security event are emitted and the function returns so the
            caller may engage its degraded path.
    """
    if unsandboxed_optout_active():
        logger.warning(
            "SANDBOX WAIVED for %s: core.sandbox is unavailable (%s) and "
            "%s=1 is set — the tool runs as a bare subprocess with NO "
            "isolation. Untrusted input can compromise this host.",
            tool, exc, ALLOW_UNSANDBOXED_ENV,
        )
        log_security_event(
            "unsandboxed_tool_fallback",
            f"sandbox isolation waived via {ALLOW_UNSANDBOXED_ENV}=1 "
            f"for {tool} (core.sandbox unavailable)",
            tool=tool,
        )
        return
    raise SandboxUnavailableError(
        f"core.sandbox is unavailable ({exc!r}) — {tool} refuses to run "
        f"without sandbox isolation (it consumes untrusted input). "
        f"Remedy: run RAPTOR on a supported platform (Linux/macOS) from "
        f"a complete install so core.sandbox imports, or — for trusted "
        f"input on a dev host only — set {ALLOW_UNSANDBOXED_ENV}=1 to "
        f"explicitly accept unsandboxed execution (logged as a "
        f"security event)."
    ) from exc
