"""WSL host-environment facts (detection and messaging only).

Two advisory questions, both answered fail-toward-False:

  * :func:`is_wsl` — is this Linux kernel a WSL (Windows Subsystem
    for Linux) kernel?  WSL kernels carry a ``microsoft`` token in
    the kernel release string (``/proc/sys/kernel/osrelease``, also
    embedded in ``/proc/version``) — WSL1 and WSL2 both.
  * :func:`fs_is_drvfs_or_9p` — does *path* live on a
    Windows-interop mount?  WSL2 serves Windows drives (the
    ``/mnt/<drive>`` automount family) over 9p, so the containing
    filesystem's ``statfs(2)`` ``f_type`` is ``V9FS_MAGIC``.

Consumers use these for messaging only: banner/doctor advisories
(:func:`wsl_advisories`) and warn-only notes when a target or output
root lands on a Windows-interop mount
(:func:`warn_windows_interop_mount`). Detection must never break or
steer a run — every error path returns False / stays silent, and
nothing here changes sandbox floors, read modes, or verdicts.
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = [
    "fs_is_drvfs_or_9p",
    "is_wsl",
    "warn_windows_interop_mount",
    "wsl_advisories",
]

#: Kernel identity sources, most specific first. ``osrelease`` is the
#: ``uname -r`` string (WSL2 kernels end in
#: ``-microsoft-standard-WSL2``); ``/proc/version`` embeds the same
#: release plus build metadata and covers WSL1, whose osrelease
#: spelling has varied across builds.
_KERNEL_ID_PATHS: tuple[str, ...] = (
    "/proc/sys/kernel/osrelease",
    "/proc/version",
)

#: 9p filesystem magic — ``V9FS_MAGIC`` in the kernel's
#: ``include/uapi/linux/magic.h``. WSL2 mounts Windows drives over a
#: 9p server, so this is the Windows-interop signal on WSL2 (the
#: WSL flavour the codebase targets). WSL1's native drvfs reports a
#: Microsoft-specific magic that does NOT appear in the kernel's
#: magic.h; matching an unverified constant is worse than missing
#: the WSL1 case, so it is deliberately not matched here — see
#: docs/wsl.md.
_V9FS_MAGIC: int = 0x01021997

_is_wsl_cache: bool | None = None


def _read_kernel_id() -> str:
    """First readable kernel identity string, or ``""``."""
    for name in _KERNEL_ID_PATHS:
        try:
            text = Path(name).read_text(encoding="ascii", errors="replace")
        except OSError:
            continue
        if text.strip():
            return text
    return ""


def is_wsl(kernel_id: str | None = None) -> bool:
    """True when the running kernel identifies as WSL.

    Matches a case-insensitive ``microsoft`` token in the kernel
    release/version string — present on WSL1 and WSL2 alike, absent
    on every mainline distro kernel. *kernel_id* injects the identity
    text (tests / callers that already hold it) and bypasses the
    cache; otherwise the filesystem answer is cached process-wide.
    Never raises: an unreadable ``/proc`` (masked in a container) or
    a non-Linux platform reads as False.
    """
    if kernel_id is not None:
        return "microsoft" in kernel_id.lower()
    global _is_wsl_cache
    if _is_wsl_cache is None:
        detected = False
        if sys.platform == "linux":
            try:
                detected = "microsoft" in _read_kernel_id().lower()
            except Exception:  # noqa: BLE001 — detection must never break a run
                logger.debug("WSL kernel-id probe failed", exc_info=True)
        _is_wsl_cache = detected
    return _is_wsl_cache


def _statfs_f_type(path: Path) -> int | None:
    """``statfs(2)`` ``f_type`` for *path*, or None on any failure.

    Python's ``os.statvfs`` wraps ``statvfs(3)``, whose struct has no
    ``f_type`` field, so the raw syscall goes through libc. Only the
    leading ``f_type`` word is read; the buffer is oversized so the
    struct tail (which differs between statfs variants) can never
    overflow it. ``f_type`` is a ``__fsword_t`` — ``c_long``-width on
    the verified ABIs (x86_64, aarch64); an exotic ABI where the
    widths diverge (e.g. x32) reads the low word, and the fail
    direction stays not-9p.
    """
    if sys.platform != "linux":
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        buf = ctypes.create_string_buffer(256)
        if libc.statfs(os.fsencode(str(path)), buf) != 0:
            return None
        return int(ctypes.c_long.from_buffer_copy(buf, 0).value)
    except Exception:  # noqa: BLE001 — detection must never break a run
        logger.debug("statfs probe failed for %s", path, exc_info=True)
        return None


def fs_is_drvfs_or_9p(path: str | os.PathLike) -> bool:
    """True when *path* lives on a Windows-interop (9p) mount.

    Matches ``V9FS_MAGIC`` — the transport WSL2 serves Windows drives
    over (the drvfs role on WSL2). A path that does not exist yet
    (run directories are resolved before creation) probes its nearest
    existing ancestor: that is the filesystem the path would be
    created on. Never raises; every failure reads as False.
    """
    try:
        p = Path(path).resolve()
        while not p.exists() and p != p.parent:
            p = p.parent
        f_type = _statfs_f_type(p)
    except Exception:  # noqa: BLE001 — detection must never break a run
        logger.debug("drvfs/9p probe failed", exc_info=True)
        return False
    return f_type == _V9FS_MAGIC


def wsl_advisories(landlock_ok: bool) -> list[str]:
    """WSL-specific advisory lines for the banner/doctor warning list.

    Empty off-WSL. Reuses probe results the caller already gathered
    (*landlock_ok* from ``core.sandbox.check_landlock_available``);
    its own lookups are ``shutil.which`` presence checks only — no
    new probes, and no probe result is changed. Never raises.
    """
    if not is_wsl():
        return []
    import shutil

    out: list[str] = []
    if not landlock_ok:
        # Mirrors the per-spawn fail-closed message in
        # core/sandbox/landlock.py: name BOTH remedies — a kernel
        # with Landlock, or explicit consent to a containment floor
        # that admits the ns-only tier.
        out.append(
            "WSL: stock WSL2 kernels ship without Landlock, so runs "
            "whose containment floor requires the Landlock layer "
            "fail closed. Use a custom kernel with Landlock enabled "
            "(.wslconfig `kernel=` — recipe in docs/wsl.md), or "
            "consent to a containment floor that admits the ns-only "
            "tier (`--sandbox-floor ns-only` per run, "
            "`/project set sandbox-floor ns-only` standing)."
        )
    if shutil.which("rr"):
        out.append(
            "rr requires CPU perf counters, typically unavailable "
            "under WSL2 — /crash-analysis recording is likely to "
            "fail on this host (see docs/wsl.md)"
        )
    if not shutil.which("docker"):
        out.append(
            "docker not found — on WSL, enable Docker Desktop's WSL "
            "integration for this distro or install Docker Engine "
            "inside it (see docs/wsl.md)"
        )
    return out


def warn_windows_interop_mount(path: str | os.PathLike, role: str) -> None:
    """Warn-only advisory when *path* is on a Windows-interop mount.

    One line naming what degrades there — file I/O speed and flock
    semantics (client-local on 9p: locks are not shared with Windows
    or other distros) — with the docs/wsl.md pointer. Fires only on
    WSL hosts (cached :func:`is_wsl` short-circuits everywhere else,
    so non-WSL runs never pay the statfs). *role* is a caller-owned
    constant naming which path this is ("default target", "output
    directory", ...). Advisory only: never raises, never refuses.
    """
    try:
        if not is_wsl() or not fs_is_drvfs_or_9p(path):
            return
        # Same escape discipline as the volatile-target banner in
        # core/run/output.py: the path can carry operator-external
        # bytes, and the bare stderr print (unlike the logger lane)
        # has no console formatter to escape them.
        from core.security.log_sanitisation import sanitise_for_terminal
        line = (
            f"WARNING: {role} "
            f"{sanitise_for_terminal(str(path), max_len=256)} is on a "
            f"Windows-interop mount (drvfs/9p): file I/O is "
            f"substantially slower there and flock locks are "
            f"client-local (not shared with Windows or other "
            f"distros). Prefer a path on the distro's Linux "
            f"filesystem. See docs/wsl.md."
        )
        logger.warning("%s", line)
        print(line, file=sys.stderr)
    except Exception:  # noqa: BLE001 — advisory must never break a run
        logger.debug("windows-interop mount advisory failed", exc_info=True)
