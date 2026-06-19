"""Frida / dynamic-instrumentation capability detection.

Probes the host for the pieces ``/frida`` needs - the ``frida`` Python
binding, the ``frida`` CLI, and the kernel ``ptrace_scope`` setting - and
reports them rather than failing mid-run with a cryptic error. Mirrors the
``packages/fuzzing/capability.py`` ``CapabilityReport`` pattern.

Backend-agnostic naming (``dynamic_instrumentation``, not ``frida``) so a
second backend could slot in behind the same report, the way ``fuzzing``
abstracts AFL++/libFuzzer.
"""

from __future__ import annotations

import logging
import platform
import shutil
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CapabilityReport:
    """What dynamic instrumentation can do on this host."""

    platform: str
    arch: str
    frida_python: Optional[str] = None   # frida.__version__ or None
    frida_cli: Optional[str] = None      # path to `frida` CLI or None
    ptrace_scope: Optional[int] = None   # /proc/sys/kernel/yama/ptrace_scope
    notes: List[str] = field(default_factory=list)

    @property
    def available(self) -> bool:
        """True when the Python binding is importable - the embedded driver
        (spawn + Stalker) only needs the binding, not the CLI."""
        return self.frida_python is not None

    def summary(self) -> str:
        if not self.available:
            return ("frida Python binding not importable - /frida unavailable. "
                    "Install with: pipx install frida-tools  (or "
                    "pip install frida-tools)")
        bits = [f"frida {self.frida_python}"]
        if self.frida_cli:
            bits.append("CLI present")
        if self.ptrace_scope is not None:
            bits.append(f"ptrace_scope={self.ptrace_scope}")
        return ", ".join(bits)


def _read_ptrace_scope() -> Optional[int]:
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def probe() -> CapabilityReport:
    """Static capability probe - no process is spawned (cheap, safe to call
    from ``/doctor``). Runtime spawn-vs-namespace fallback is handled by the
    runner, not here."""
    rep = CapabilityReport(
        platform=platform.system(),
        arch=platform.machine(),
        frida_cli=shutil.which("frida"),
        ptrace_scope=_read_ptrace_scope(),
    )
    try:
        import frida  # noqa: F401
        rep.frida_python = getattr(frida, "__version__", "unknown")
    except Exception as e:  # noqa: BLE001 - probe must never raise
        rep.notes.append(f"frida import failed: {type(e).__name__}: {e}")
    if rep.ptrace_scope is not None and rep.ptrace_scope >= 2:
        rep.notes.append(
            "ptrace_scope >= 2: attach-to-PID is restricted; spawn-mode "
            "(the /frida default) is unaffected.")
    return rep
