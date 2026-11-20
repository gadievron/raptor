"""Executable staging for run-dir artifacts.

Env-built artifacts are extracted mode 0444 (``core/env/build.py``
strips execute/setuid/setgid: the bytes came from the attacker's
build, and the run dir must never hold an executable file). The
dynamic tier is allowed to RUN those bytes — but only behind its
explicit consent gates and inside the sandbox. This module bridges
the two invariants: at the consented exec point, stage a private
0o500 copy in a fresh owner-only temp dir and exec the copy. The
original artifact and the run dir stay non-executable throughout;
without the staging step the sandbox child's execve fails EACCES,
which the spawn layer reports as a per-invocation spawn failure
("X: exec: permission denied") and the whole dynamic probe degrades.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from core.run.scratch import scratch_dir
from core.run.workdir import exec_workdir

from ._pathpin import open_pinned


def _open_verified_source(raw: str, gate_st: os.stat_result) -> int:
    """Open the staging source read-only, bound to the gated inode.

    On Linux the whole path is first re-walked with a symlink-refusing
    component walk (:func:`core.sandbox._pathpin.open_pinned`) — a
    component swapped to a symlink between the lstat gate and the copy
    raises ELOOP instead of being followed, and the walked inode must
    be the one the gate cleared. On every platform the fd actually
    opened for the copy is fstat-matched against the gate's
    ``(st_dev, st_ino)``: whatever the path resolved to at open time,
    the bytes copied are exactly the gated file's. A mismatch raises
    ESTALE — the source changed underneath the gate.
    """
    if hasattr(os, "O_PATH"):
        pin = open_pinned(raw)
        try:
            pin_st = os.fstat(pin)
        finally:
            os.close(pin)
        if (pin_st.st_dev, pin_st.st_ino) != (gate_st.st_dev,
                                              gate_st.st_ino):
            raise OSError(
                errno.ESTALE,
                f"exec-stage source {raw!r} changed between the lstat "
                f"gate and the pinned walk; refusing to stage")
    fd = os.open(
        raw, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        src_st = os.fstat(fd)
        if (src_st.st_dev, src_st.st_ino) != (gate_st.st_dev,
                                              gate_st.st_ino):
            raise OSError(
                errno.ESTALE,
                f"exec-stage source {raw!r} changed between the lstat "
                f"gate and the open; refusing to stage")
    except BaseException:
        os.close(fd)
        raise
    return fd


@contextmanager
def executable_stage(binary_path: str | os.PathLike) -> Iterator[Path]:
    """Yield a runnable path for *binary_path*.

    An already-executable file — a self-compiled harness, an
    operator-supplied binary — is yielded unchanged, as is anything
    that is not a regular file (the caller's existing missing-binary
    handling stays authoritative). A non-executable regular file (the
    env-built 0444 shape) is copied into a fresh ``mkdtemp``-private
    directory with mode 0o500 and the copy is yielded; everything is
    removed when the context exits. The copy keeps the original
    basename: address-space consumers match ``/proc/<pid>/maps``
    entries by name.

    Symlinks are never staged — in ANY path component, not just the
    leaf: the artifact lives in a run dir earlier sandboxed children
    could write, and callers pass target-repo build paths, so a planted
    link (``build -> ~/.ssh`` as much as a linked leaf) would make the
    parent-side copy read (and re-expose, executable) a file the child
    itself could not. A path whose resolution traverses any symlink is
    yielded unchanged, like the stable leaf-link shape. A symlink or
    inode swap raced in AFTER that check is refused loudly: the source
    open re-walks the path with a symlink-refusing component walk
    (Linux) and binds the opened fd to the lstat-gated inode by
    (st_dev, st_ino) on every platform.

    The staging dir lives under :func:`core.run.workdir.exec_workdir`
    (executable even when the system tmp is mounted noexec, swept with
    the session); the ``raptor-exec-stage-`` prefix is additionally
    reaper-registered so the default-temp-dir fallback cannot strand
    an executable copy past a SIGKILL.
    """
    p = Path(binary_path)
    try:
        st = os.lstat(p)
    except OSError:
        yield p
        return
    if not stat.S_ISREG(st.st_mode) or os.access(p, os.X_OK):
        yield p
        return
    raw = os.path.abspath(os.fspath(p))
    if os.path.realpath(raw) != raw:
        # Some component of the path is (or just became) a symlink.
        # Never staged, same pass-through as the leaf-link shape.
        yield p
        return
    with scratch_dir("raptor-exec-stage-", dir=exec_workdir()) as td:
        staged = Path(td) / p.name
        src_fd = _open_verified_source(raw, st)
        with os.fdopen(src_fd, "rb") as src, open(staged, "xb") as dst:
            shutil.copyfileobj(src, dst)
        staged.chmod(0o500)
        yield staged
