"""Anchored opens beneath a root directory — the ONE home for the
dir-fd walk idiom.

:func:`core.paths.confine` is resolve-then-open: it proves the
candidate resolves under the root at CHECK time, but the open that
follows re-resolves the whole path by name, so an attacker with
concurrent write access inside the tree can swap an INTERMEDIATE
directory for an out-of-tree symlink between the check and the open
and steer the read out of root. :func:`open_regular_beneath` closes
that window: after the caller has resolved and contained the path,
the open itself re-walks it ANCHORED — every step relative to an fd
already inside the root, never re-resolving from ``/`` — so a
post-check swap refuses instead of escaping.

Mechanics (contract identical on every platform, with one stated
exception: a joined path past PATH_MAX refuses on the openat2 route
with ``ENAMETOOLONG`` while the component walk can still open it —
fail-closed, never fail-open):

- The root opens ``O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC``
  and is fstat-verified ``S_ISDIR``.
- ``rel`` must be relative with no ``..`` segments (same rule as
  ``core.sandbox._pathpin.open_pinned`` — resolved output never
  contains them; refusing up-front beats walking upward).
- Fast path (Linux 5.6+): one ``openat2(2)`` with ``RESOLVE_BENEATH |
  RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`` — the kernel enforces
  in-one-syscall exactly what the walk enforces stepwise.
  ``RESOLVE_NO_SYMLINKS`` (not just BENEATH) so the fast path and the
  fallback refuse the SAME shapes: the component walk cannot follow a
  link safely, so neither may the fast path — callers that
  legitimately traverse in-root symlinks resolve FIRST (confine /
  realpath) and hand the resolved rel here, exactly the
  ``_pathpin.open_pinned`` usage contract.
- Fallback (older kernels, macOS, any ``openat2`` refusal to engage):
  per-component ``openat(dir_fd, comp, O_RDONLY | O_DIRECTORY |
  O_NOFOLLOW)`` — a swapped-in symlink refuses with ``ELOOP``
  (``ENOTDIR`` for a non-directory) — then the final component opens
  ``O_NOFOLLOW | O_NONBLOCK`` and is fstat-verified ``S_ISREG`` on
  the OPENED fd (never by name): FIFOs/devices refuse instead of
  blocking, symlinks refuse instead of following.

Siblings, deliberately not merged:

- ``core.sandbox._pathpin.open_pinned`` — O_PATH pin for mount/grant
  SOURCES: fork-safe (os-syscall-wrappers only, callable from preexec
  closures), Linux-only by contract, returns an O_PATH fd for
  ``/proc/self/fd`` mount targeting rather than a readable file
  object. Same walk doctrine, different substrate constraints — a
  reader helper importable at leisure cannot serve a preexec closure,
  so the two bodies stay separate with cross-references.
- ``libexec/raptor-fetch-attachment._open_attachments_dir`` — the
  write-side dir flavor (it mkdirs mid-walk); adopts a shared
  ``open_dir_beneath`` when that flavor earns a second consumer.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import platform
import stat
from pathlib import Path, PurePosixPath
from typing import IO

__all__ = ["open_regular_beneath"]

_O_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_O_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
)

# openat2(2) — asm-generic syscall table (all post-2011 architectures;
# same arch gate as the Landlock syscalls in core/sandbox/landlock.py:
# older tables map the number elsewhere, MIPS n64 offsets by 5000).
_SYS_OPENAT2 = 437
_OPENAT2_ARCH_OK = platform.machine() in (
    "x86_64", "aarch64", "riscv64", "loongarch64", "s390x",
)
# include/uapi/linux/openat2.h
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08

#: Tri-state openat2 availability: None = unprobed, True/False after
#: the first call. A refusal-class errno never flips this — only
#: "the syscall itself is unusable" shapes do.
_openat2_usable: bool | None = None
_libc: ctypes.CDLL | None = None


class _OpenHow(ctypes.Structure):
    _fields_ = (
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    )


def _openat2_beneath(root_fd: int, rel: str) -> int | None:
    """One-syscall anchored open. Returns the fd, ``None`` for a
    refusal (escape attempt, symlink, missing file), and raises
    :class:`NotImplementedError` when openat2 itself is unusable so
    the caller falls back to the component walk."""
    global _libc, _openat2_usable
    if _openat2_usable is False:
        raise NotImplementedError
    if _libc is None:
        try:
            _libc = ctypes.CDLL(ctypes.util.find_library("c"),
                                use_errno=True)
        except (OSError, TypeError):
            _openat2_usable = False
            raise NotImplementedError from None
    libc = _libc
    how = _OpenHow(
        flags=_O_FILE_FLAGS,
        mode=0,
        resolve=(
            _RESOLVE_BENEATH | _RESOLVE_NO_SYMLINKS | _RESOLVE_NO_MAGICLINKS
        ),
    )
    # os.fsencode, not str.encode: surrogate-escaped (non-UTF-8)
    # filenames from hostile trees must round-trip to the same bytes
    # the walk's os.open uses, or the two routes diverge (strict
    # encode raises UnicodeEncodeError through every consumer).
    rel_bytes = os.fsencode(rel)
    while True:
        fd = libc.syscall(
            _SYS_OPENAT2,
            ctypes.c_int(root_fd),
            rel_bytes,
            ctypes.byref(how),
            ctypes.c_size_t(ctypes.sizeof(how)),
        )
        if fd >= 0:
            _openat2_usable = True
            return int(fd)
        err = ctypes.get_errno()
        if err != errno.EINTR:
            break
        # PEP 475 does not cover a raw ctypes syscall: retry EINTR
        # like os.open would, instead of misreading a signal as a
        # per-path refusal.
    if err in (errno.ENOSYS, errno.E2BIG, errno.EINVAL, errno.EPERM):
        # Kernel without openat2 / without these resolve flags, or a
        # seccomp policy denying it — the walk provides the identical
        # contract, so degrade silently. EINVAL and E2BIG are the
        # documented "unknown flags / unknown fields" shapes on older
        # kernels; EPERM is the common seccomp default-deny mapping.
        _openat2_usable = False
        raise NotImplementedError
    # EXDEV = RESOLVE_BENEATH escape refusal; ELOOP = symlink refusal;
    # ENOENT/ENOTDIR = vanished or non-dir component. All are answers
    # about THIS path, not about openat2 — refuse, don't fall back
    # (a fallback would just re-derive the same refusal stepwise).
    _openat2_usable = True
    return None


def _walk_beneath(root_fd: int, parts: tuple[str, ...]) -> int | None:
    """Per-component anchored open of ``parts`` under *root_fd*.

    Every ``openat`` is relative to the previous component's fd with
    ``O_NOFOLLOW``, so there is no window in which the kernel
    re-resolves the already-vetted prefix from ``/`` — a concurrent
    swap of any component refuses (``ELOOP``/``ENOTDIR``/``ENOENT``)
    instead of redirecting the walk.
    """
    fd = -1
    try:
        for comp in parts[:-1]:
            nxt = os.open(comp, _O_DIR_FLAGS,
                          dir_fd=(fd if fd >= 0 else root_fd))
            if fd >= 0:
                os.close(fd)
            fd = nxt
        return os.open(parts[-1], _O_FILE_FLAGS,
                       dir_fd=(fd if fd >= 0 else root_fd))
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def open_regular_beneath(
    root: str | Path,
    rel: str | Path,
    mode: str = "r",
    **kwargs,
) -> IO | None:
    """Open ``root/rel`` for reading iff every step of the open stays
    anchored beneath *root* and the final inode is a regular file.

    *rel* must be relative and free of ``..`` segments — callers hand
    in the output of :func:`core.paths.confine` (resolved, contained)
    made relative to the resolved root, or an otherwise pre-resolved
    relative path. Symlinks ANYWHERE in *rel* refuse: at open time a
    link can only be a post-containment swap (resolution already
    happened) or an unvetted redirect (it never did) — resolve first
    to traverse benign in-root links.

    Returns a file object (``os.fdopen``; *mode* must be a read mode,
    ``"r"``/``"rb"``), or ``None`` on any refusal: escaping or
    absolute *rel*, swapped/planted symlink, FIFO/device/directory
    final inode (fstat on the OPENED fd; ``O_NONBLOCK`` keeps even
    the open of a reader-less FIFO from hanging), or plain
    ``OSError``. Raises ``ValueError`` only for a caller-bug *mode*
    (write/append modes never belong on this helper).
    """
    if mode not in ("r", "rb"):
        msg = f"open_regular_beneath is a reader: bad mode {mode!r}"
        raise ValueError(msg)
    rel_str = str(rel)
    if "\x00" in rel_str:
        # An embedded NUL truncates the C string the openat2 fast
        # path passes to the kernel (opening a DIFFERENT in-root name
        # than requested) and raises ValueError — not OSError — from
        # the walk's os.open. Refuse the spelling outright so both
        # routes agree.
        return None
    rel_pure = PurePosixPath(rel_str)
    if rel_pure.is_absolute():
        return None
    parts = tuple(c for c in rel_pure.parts if c not in ("", "."))
    if not parts or ".." in parts:
        return None
    try:
        root_fd = os.open(str(root), _O_DIR_FLAGS)
    except OSError:
        return None
    fd: int | None = None
    try:
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            return None
        if _OPENAT2_ARCH_OK:
            try:
                fd = _openat2_beneath(root_fd, "/".join(parts))
            except NotImplementedError:
                fd = _walk_beneath(root_fd, parts)
        else:
            fd = _walk_beneath(root_fd, parts)
        if fd is None:
            return None
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            fd = None
            return None
        out = os.fdopen(fd, mode, **kwargs)
        fd = None  # fdopen owns it now
        return out
    except OSError:
        if fd is not None:
            os.close(fd)
        return None
    finally:
        os.close(root_fd)
