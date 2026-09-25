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
  * :func:`is_wsl2` / :func:`is_wsl1` — which WSL flavour?
    :func:`is_wsl` is True for BOTH; the flavour split matters
    because WSL2 runs a real Linux kernel while WSL1 emulates
    syscalls (no namespaces, Landlock, or seccomp — nothing for a
    sandbox to stand on).

The messaging consumers (banner/doctor advisories via
:func:`wsl_advisories`, the warn-only Windows-interop-mount notes via
:func:`warn_windows_interop_mount`) must never break or steer a run —
every error path returns False / stays silent. The sandbox layer
additionally consumes :func:`is_wsl` (WSL-only profile masks and the
/mnt ambient-read deny — deny-direction hardening only) and
:func:`is_wsl1` (refusing sandboxed execution where no kernel
enforcement exists); those consumers keep the same never-raise
contract, and a probe failure still reads as plain Linux.
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
    "is_wsl1",
    "is_wsl2",
    "warn_tmpdir_windows_interop",
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

#: WSL2 flavour token. WSL2 kernel releases carry
#: ``-microsoft-standard`` (modern builds append ``-WSL2``:
#: ``5.15.167.4-microsoft-standard-WSL2``; early WSL2 previews ended
#: at ``-microsoft-standard``). WSL1's syscall-emulation layer
#: reports spellings like ``4.4.0-19041-Microsoft`` — the
#: ``microsoft`` token without ``microsoft-standard``. Fail
#: direction: a WSL identity that matches :func:`is_wsl` but not
#: this token classifies as WSL1, and the sandbox consumer REFUSES
#: on WSL1 — so an unrecognised WSL flavour fails toward refusal
#: (loud, with the WSL2 upgrade named), never toward pretending a
#: kernel exists.
_WSL2_TOKEN = "microsoft-standard"

_is_wsl_cache: bool | None = None
_is_wsl2_cache: bool | None = None


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


def is_wsl2(kernel_id: str | None = None) -> bool:
    """True when the running kernel identifies as WSL2 specifically.

    :func:`is_wsl` is True for BOTH WSL flavours; this discriminator
    matches the ``microsoft-standard`` release token that only WSL2
    kernels carry (see ``_WSL2_TOKEN`` for the spellings and the fail
    direction). Same contract as :func:`is_wsl`: *kernel_id* injects
    the identity text and bypasses the cache; otherwise the
    filesystem answer is cached process-wide, and every failure reads
    as False.
    """
    if kernel_id is not None:
        return is_wsl(kernel_id) and _WSL2_TOKEN in kernel_id.lower()
    global _is_wsl2_cache
    if _is_wsl2_cache is None:
        detected = False
        if is_wsl():
            try:
                detected = _WSL2_TOKEN in _read_kernel_id().lower()
            except Exception:  # noqa: BLE001 — detection must never break a run
                logger.debug("WSL2 kernel-id probe failed", exc_info=True)
        _is_wsl2_cache = detected
    return _is_wsl2_cache


def is_wsl1(kernel_id: str | None = None) -> bool:
    """True when the running kernel identifies as WSL1.

    Derived, never separately probed: WSL minus the WSL2 flavour
    token (``is_wsl() and not is_wsl2()``), so :func:`is_wsl`'s
    semantics are untouched and the three predicates can never
    disagree. WSL1 emulates Linux syscalls on the NT kernel — no
    namespaces, no Landlock, no seccomp — so the sandbox consumer
    refuses execution outright rather than "degrading" to layers
    that do not exist there.
    """
    if kernel_id is not None:
        return is_wsl(kernel_id) and not is_wsl2(kernel_id)
    return is_wsl() and not is_wsl2()


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
    its own lookups are ``shutil.which`` presence checks plus one
    ``statfs`` of the temp root (WSL hosts only) — no probe result
    is changed. Never raises.
    """
    if not is_wsl():
        return []
    import shutil

    out: list[str] = []
    if not landlock_ok:
        # Host-consent posture: when the operator's standing marker
        # (core/sandbox/host_consent.py) currently APPLIES, the
        # refusal advisory below would be stale — runs proceed at the
        # consented ns-only tier — so the section states the posture
        # instead: the tier, the grant date, and the revoke/override
        # surfaces. Never raises; a probe failure falls back to the
        # refusal advisory (the fail-closed story stays accurate).
        consent = None
        try:
            from core.sandbox.host_consent import applied_consent
            consent = applied_consent()
        except Exception:  # noqa: BLE001 — advisory must never break startup
            logger.debug("host-consent posture probe failed",
                         exc_info=True)
        if consent is not None:
            out.append(
                f"WSL: untrusted floor ns-only by host consent, "
                f"granted {consent.granted_at[:10]} — Landlock "
                f"unavailable on this kernel. Revoke: `bin/raptor "
                f"wsl-consent revoke`; a per-run --sandbox-floor or "
                f"the project sandbox-floor setting overrides "
                f"(see docs/wsl.md)."
            )
        else:
            # Mirrors the per-spawn fail-closed message in
            # core/sandbox/landlock.py: name the remedies — a kernel
            # with Landlock, explicit consent to a containment floor
            # that admits the ns-only tier, or the standing
            # host-scoped consent ceremony.
            out.append(
                "WSL: stock WSL2 kernels ship without Landlock, so runs "
                "whose containment floor requires the Landlock layer "
                "fail closed. Use a custom kernel with Landlock enabled "
                "(.wslconfig `kernel=` — recipe in docs/wsl.md), "
                "consent to a containment floor that admits the ns-only "
                "tier (`--sandbox-floor ns-only` per run, "
                "`/project set sandbox-floor ns-only` standing), or "
                "grant the standing host-scoped consent at your "
                "terminal (`bin/raptor wsl-consent grant`, TTY-gated)."
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
    import tempfile
    tmp_root = tempfile.gettempdir()
    if fs_is_drvfs_or_9p(tmp_root):
        from core.security.log_sanitisation import sanitise_for_terminal
        out.append(
            "the temp root "
            f"{sanitise_for_terminal(str(tmp_root), max_len=256)} is on "
            "a Windows-interop mount (drvfs/9p): FIFO/named-pipe "
            "creation fails there and many-small-file scratch work is "
            "drastically slower. Point TMPDIR at a path on the "
            "distro's Linux filesystem (e.g. `export TMPDIR=/tmp`) "
            "before launching (see docs/wsl.md)"
        )
    return out


def warn_windows_interop_mount(
    path: str | os.PathLike, role: str, *, detail: str = "",
) -> None:
    """Warn-only advisory when *path* is on a Windows-interop mount.

    One line naming what degrades there — file I/O speed and flock
    semantics (client-local on 9p: locks are not shared with Windows
    or other distros) — with the docs/wsl.md pointer. Fires only on
    WSL hosts (cached :func:`is_wsl` short-circuits everywhere else,
    so non-WSL runs never pay the statfs). *role* is a caller-owned
    constant naming which path this is ("default target", "output
    directory", ...); *detail*, when given, is a caller-owned
    constant sentence replacing the generic "prefer a Linux
    filesystem path" remedy with role-specific breakage/remediation
    text (never external/target-derived — only *path* is escaped).
    Advisory only: never raises, never refuses.
    """
    try:
        if not is_wsl() or not fs_is_drvfs_or_9p(path):
            return
        # Same escape discipline as the volatile-target banner in
        # core/run/output.py: the path can carry operator-external
        # bytes, and the bare stderr print (unlike the logger lane)
        # has no console formatter to escape them.
        from core.security.log_sanitisation import sanitise_for_terminal
        remedy = detail or (
            "Prefer a path on the distro's Linux filesystem."
        )
        line = (
            f"WARNING: {role} "
            f"{sanitise_for_terminal(str(path), max_len=256)} is on a "
            f"Windows-interop mount (drvfs/9p): file I/O is "
            f"substantially slower there and flock locks are "
            f"client-local (not shared with Windows or other "
            f"distros). {remedy} See docs/wsl.md."
        )
        logger.warning("%s", line)
        print(line, file=sys.stderr)
    except Exception:  # noqa: BLE001 — advisory must never break a run
        logger.debug("windows-interop mount advisory failed", exc_info=True)


#: Role + remedy constants for the temp-root advisory. Caller-owned
#: constants by the ``warn_windows_interop_mount`` contract; the
#: remedy names what BREAKS on a 9p temp root (not just what slows
#: down): FIFO/named-pipe creation is unsupported there, and scratch
#: workloads are many-small-file by nature — the worst shape for
#: per-file 9p round-trips. See docs/wsl.md.
_TMPDIR_ROLE = "temp root (TMPDIR/RAPTOR_WORK_DIR)"
_TMPDIR_DETAIL = (
    "Temp-backed features break there, not just slow down: "
    "FIFO/named-pipe creation fails on 9p, and many-small-file "
    "scratch work is drastically slower. Point TMPDIR (and "
    "RAPTOR_WORK_DIR, when set) at a path on the distro's Linux "
    "filesystem (e.g. `export TMPDIR=/tmp`) before launching."
)

_tmpdir_warned = False


def warn_tmpdir_windows_interop(
    base: str | os.PathLike | None = None,
) -> None:
    """At most one strong advisory per process when the temp root the
    caller resolved is on a drvfs/9p mount.

    THE latch for the scratch/temp-root chokepoints
    (:func:`core.run.scratch.scratch_dir`,
    :func:`core.run.workdir.exec_workdir`): each may call this on
    every lane/resolution, and at most one warning per process is
    emitted. *base* is the chokepoint's own RESOLVED root when it
    honours more than ``TMPDIR`` (workdir's ``RAPTOR_WORK_DIR``
    precedence); ``None`` probes :func:`tempfile.gettempdir`. The
    latch closes on first call regardless of outcome — the first
    chokepoint reached decides for the process (gettempdir() itself
    caches process-wide, so the plain-TMPDIR verdict cannot change
    later). Off-WSL the first call costs one cached ``is_wsl()``
    check and every later call is a single boolean test. Advisory
    only: never raises, never refuses, never changes where scratch
    is created.
    """
    global _tmpdir_warned
    if _tmpdir_warned:
        return
    _tmpdir_warned = True
    if base is None:
        import tempfile
        base = tempfile.gettempdir()
    warn_windows_interop_mount(base, _TMPDIR_ROLE, detail=_TMPDIR_DETAIL)
