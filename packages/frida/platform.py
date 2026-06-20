"""Platform detection for Frida runs.

Frida's behaviour differs meaningfully across host platforms - most
notably, macOS attach to system-owned processes requires SIP-disabled
or task_for_pid entitlements, while Linux attach needs ptrace
permission (kernel.yama.ptrace_scope). We surface these in the
metadata.json a run drops so an operator looking at a failed attach
later can see *why*.

The helpers here are deliberately small - no platform-specific code
paths in the runner itself; just labels and reachability checks.
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class HostInfo:
    """Snapshot of host-side preconditions for a Frida run.

    Persisted into ``metadata.json`` so post-hoc inspection of a
    failed attach has the host posture without needing to re-derive
    it. ``frida_version`` is best-effort - falls back to "unknown"
    if the binding isn't importable.
    """
    system: str            # "Darwin", "Linux", "Windows"
    arch: str              # "arm64", "x86_64", etc.
    frida_version: str     # frida-python version
    frida_bin: str | None  # resolved path to `frida` CLI, if any
    sip_status: str | None # macOS only: "enabled" / "disabled" / "unknown"
    ptrace_scope: int | None  # Linux only: /proc/sys/kernel/yama/ptrace_scope


def detect_host() -> HostInfo:
    """Snapshot the host. Pure read; never raises."""
    sys_name = platform.system()
    arch = platform.machine()

    try:
        import frida  # type: ignore
        version = getattr(frida, "__version__", "unknown")
    except Exception:
        version = "unavailable"

    return HostInfo(
        system=sys_name,
        arch=arch,
        frida_version=version,
        frida_bin=shutil.which("frida"),
        sip_status=_macos_sip_status() if sys_name == "Darwin" else None,
        ptrace_scope=_linux_ptrace_scope() if sys_name == "Linux" else None,
    )


def _macos_sip_status() -> str:
    # `csrutil status` is the canonical query but exits non-zero on
    # some restricted environments. We don't shell out - the rare
    # information is "we couldn't tell". `nvram` reflection of csr is
    # also restricted on modern macOS. Return "unknown" and let the
    # operator check manually if a system-process attach fails.
    return "unknown"


def _linux_ptrace_scope() -> int | None:
    path = "/proc/sys/kernel/yama/ptrace_scope"
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None
