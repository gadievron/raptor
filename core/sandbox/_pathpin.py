"""Symlink-refusing O_PATH pinning for mount/grant sources.

Generalisation of the ``.audit`` evidence-shadow fix (O_PATH |
O_NOFOLLOW dirfd + ``/proc/self/fd`` mount targeting) to every
attacker-adjacent bind SOURCE and Landlock grant open: host-root-mode
``target=`` / ``output=`` / ``readable_paths`` bind sources and the
Landlock writable/readable rule opens were pathname-resolved at
mount/grant time, so a concurrent sibling sandbox sharing a writable
output tree could rmdir+symlink-swap a path component between the
parent's validation and the mount(2)/add_rule(2) — steering a bind (or
a WRITE grant) onto an arbitrary host directory.

Usage contract:

1. The caller canonicalises with ``os.path.realpath`` IMMEDIATELY
   before the walk, so benign pre-existing symlinks (usrmerge ``/bin``,
   symlinked home trees) resolve normally.
2. :func:`open_pinned` walks the canonical path component-by-component
   with ``openat(..., O_PATH | O_NOFOLLOW)``. Any symlink encountered
   mid-walk appeared AFTER canonicalisation — the swap this module
   exists to refuse — and surfaces as ``OSError(ELOOP)``.
3. The returned O_PATH fd names exactly the walked inode. Mount
   callers bind ``/proc/self/fd/<fd>`` (the magic-link resolves to the
   pinned inode with no re-resolution window); Landlock callers hand
   the fd to ``path_beneath`` directly.

Scope, stated precisely. What a single walk closes depends on WHEN the
caller runs it:

* CLOSED everywhere: the post-canonicalisation swap. A symlink that
  appears between the ``realpath`` call and the mount/add_rule is
  refused (ELOOP), so the classic validate-then-mount race no longer
  steers a bind or grant.
* CLOSED for mount-ns bind sources (target= / output= / rootfs= /
  readable_paths): the pre-planted class. The spawn parent runs this
  walk at VALIDATION time (``_spawn._pin_bind_sources``, before the
  fork) and the returned fd rides the fork into the mount-ns child,
  which refuses each bind unless its mount-time walk resolves to the
  SAME inode the validation walk pinned (identity check against the
  held fd, which also keeps that inode's (st_dev, st_ino) from being
  recycled; the fd cannot be mounted directly — mount(2) rejects
  bind sources on a foreign-mount-namespace vfsmount). So a symlink
  planted any time after the caller-side validation (the whole
  fork/newuidmap/mount window included) cannot steer a bind — it can
  only fail the spawn loudly. What remains there is irreducible at
  this layer: a symlink already resolving when the caller validates
  the path is indistinguishable from operator intent (usrmerge
  ``/bin``, symlinked home trees).
* CLOSED for Landlock grant opens: the same validation-time treatment
  as the mount-ns bind sources. ``landlock._resolve_grant_paths``
  realpaths every writable/readable rule path in the PARENT when the
  preexec closure is built, and the forked child walks the
  pre-resolved canonical string — a symlink planted anywhere in the
  fork/grant window refuses (ELOOP) and the rule falls under the
  global deny. The confined-sibling escalation motivated closing this
  (a Landlock-confined planter with MAKE_SYM on a shared output tree
  could otherwise steer the NEXT sandbox's WRITE grant onto a tree the
  planter itself could not write — the same-UID-DAC argument does not
  cover that case). What remains is the irreducible pre-validation
  class below, announced once per redirect in the run log.
* REMAINS window-narrowed (walk-time only) for etc_overlay sources: a
  symlink pre-planted before THAT walk's ``realpath`` resolves like a
  benign operator symlink and pins the attacker's chosen destination.
  Deliberate scoping, not an oversight: etc_overlay sources are
  caller-work-dir-internal files, not attacker-adjacent trees.
* Also remains: a rename-swap to a REAL directory the attacker
  already controls — that grants access only to content they could
  already write. The validation-time identity check is likewise
  inode-identity, not path-identity: relocating the VALIDATED inode
  itself (mv + symlink back to its new location) still passes, and
  confers nothing — the bind lands on exactly the directory the
  caller validated, wherever it now sits.

Fork-safety: only ``os`` syscall wrappers and str/bytes ops — callable
from post-fork children and preexec functions (same constraints as
core/sandbox/landlock.py / mount_ns.py setup code).
"""

from __future__ import annotations

import errno
import os
import stat as _stat

__all__ = ["open_pinned"]

# O_PATH is Linux-only; the pinned walk backs the mount-ns bind
# machinery, which never engages on platforms without it (macOS uses
# the seatbelt tier). Import must stay safe there — open_pinned raises
# at CALL time instead.
_O_PATH = getattr(os, "O_PATH", 0)
_HAVE_O_PATH = hasattr(os, "O_PATH")
_O_COMPONENT = _O_PATH | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def open_pinned(canonical_path: str) -> int:
    """Open *canonical_path* as an O_PATH fd via a symlink-refusing
    component walk.

    Requires O_PATH (Linux). On platforms without it, raises
    ``OSError(ENOSYS)`` at call time — callers on those platforms run
    the seatbelt tier and never reach the mount-ns bind path.

    ``canonical_path`` must be absolute and should be the output of
    ``os.path.realpath`` taken immediately before the call (see module
    docstring). Returns an fd the caller must ``os.close``. Raises
    ``OSError`` — ``ELOOP`` for a mid-walk symlink (the swap signal),
    ``ENOENT``/``ENOTDIR`` for vanished/replaced components — and
    ``ValueError`` for relative paths.
    """

    if not _HAVE_O_PATH:
        raise OSError(errno.ENOSYS, "O_PATH unavailable on this platform")
    if not canonical_path.startswith("/"):
        msg = f"open_pinned requires an absolute path: {canonical_path!r}"
        raise ValueError(msg)
    if ".." in canonical_path.split("/"):
        # realpath output never contains "..": reject up-front rather
        # than walk upward (or mask it behind a component ENOENT).
        msg = f"open_pinned: non-canonical path {canonical_path!r}"
        raise ValueError(msg)
    fd = os.open("/", os.O_PATH | getattr(os, "O_CLOEXEC", 0))
    try:
        for comp in canonical_path.split("/"):
            if not comp or comp == ".":
                continue
            nxt = os.open(comp, _O_COMPONENT, dir_fd=fd)
            # O_PATH|O_NOFOLLOW does NOT fail on a symlink final
            # component — it opens the LINK itself. An fstat catches
            # both shapes uniformly: a symlink anywhere in the walk is
            # the post-canonicalisation swap and must refuse.
            if _stat.S_ISLNK(os.fstat(nxt).st_mode):
                os.close(nxt)
                raise OSError(
                    errno.ELOOP,
                    f"open_pinned: component {comp!r} of "
                    f"{canonical_path!r} is a symlink "
                    f"(post-canonicalisation swap); refusing",
                )
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise
