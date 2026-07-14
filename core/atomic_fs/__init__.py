"""Shared atomic-file-write primitive.

Consumers reach here rather than reinventing the tempfile-plus-rename
dance. Semantics guaranteed:

  * A concurrent reader NEVER sees a partial file — either the old
    bytes or the new bytes, never a truncation-in-progress.
  * On success, the destination is fully committed to disk (fsync
    on the tempfile before rename, best-effort fsync of the parent
    directory after rename for power-loss durability).
  * On failure — including ``KeyboardInterrupt`` / ``BaseException``
    — the temporary is cleaned up and ``path`` is left in its prior
    state.
  * When the destination already exists, its permission bits are
    preserved (so an operator ``chmod 0o600`` isn't silently widened
    to 0o644) UNLESS an explicit ``mode=`` is passed, in which case
    the caller's mode wins.
  * The tempfile is created with ``O_EXCL | O_NOFOLLOW`` and a
    PID+TID+random suffix so:
      - a symlink squat at the tempfile path is rejected loudly
        rather than followed (defence against local attacker on a
        shared filesystem);
      - two threads in the same process racing on the same ``path``
        each get their own tempfile;
      - two processes racing (parallel CI matrix, two operators)
        each get their own tempfile.

Symlink handling at the destination path:

  * The perm probe uses ``lstat`` so we never inherit the target of
    a symlink at ``path``.
  * ``os.replace(tmp, path)`` REPLACES the symlink itself with a
    regular file — this is the standard "atomic write to path X"
    contract. If a caller wants to write through a symlink to its
    target, they should resolve the path first.

The primitive is intended for durability-critical writers (state
stores, sandbox files, credentials). Regeneratable outputs (scripts,
one-shot corpus generators) shouldn't use it — the fsync overhead is
unearned for outputs that just get re-run on failure.

Consumers:
  * ``packages/sca`` fixer / rewriter modules — via the thin
    ``packages/sca/_atomic.py`` wrapper (delegates atomic_write_text
    / atomic_write_bytes to the primitive; preserves the sca-side
    positional-args API for 15+ existing call sites).
  * Every ``core.json.save_json`` caller (threat models, checklists,
    run reports, LLM detection cache, scorecard) transitively via
    ``save_json``'s delegation.
  * Direct-call consumers: core annotations, labeled attempts, binary
    fingerprint store, witness store, coverage store, sandbox
    calibration cache, sandbox summary + audit-degraded markers.
"""

from __future__ import annotations

import os
import secrets
import stat as _stat
import threading
from pathlib import Path
from typing import Optional, Union


# Perm mask: only the low 9 bits are legal via ``mode=``. Rejects
# setuid (0o4000), setgid (0o2000), sticky (0o1000). None of the
# durability-critical consumers should be shipping files with those
# bits set; requiring an explicit path (chmod after the write) forces
# an operator to think about it.
_MODE_MASK = 0o777


def _validate_mode(mode: Optional[int]) -> None:
    """Reject ``mode`` values outside 0o000..0o777.

    Raises ``ValueError`` on anything not representable as a plain
    POSIX file mode. Explicit rejection beats silent masking: a caller
    passing ``mode=0o4755`` is either confused or trying to install a
    setuid file — either way we want to fail loud, not paper over it.
    """
    if mode is None:
        return
    if not isinstance(mode, int):
        raise ValueError(
            f"mode must be int (0o000..0o777), got {type(mode).__name__}",
        )
    if not (0 <= mode <= _MODE_MASK):
        raise ValueError(
            f"mode must be in 0o000..0o777, got 0o{mode:o}",
        )


def _resolve_effective_mode(
    path: Path,
    mode: Optional[int],
) -> int:
    """Pick the mode to apply to the new file.

    Precedence:
      1. Explicit ``mode=`` from caller wins.
      2. Else preserve existing perms if destination is a regular
         file (guards the operator-chmod case).
      3. Else default 0o644.

    Uses ``lstat`` so a symlink at ``path`` never lets us inherit
    the symlink target's perms — the atomic replace would then destroy
    the symlink AND install a file with unrelated perms. Only preserves
    when the existing entry is a regular file; symlinks / sockets /
    devices fall back to the default.
    """
    if mode is not None:
        return mode
    try:
        st = path.lstat()
    except FileNotFoundError:
        return 0o644
    # PermissionError etc propagate — an inaccessible parent is a
    # real problem the caller should see, not silently downgrade to
    # 0o644 (which would be a chmod-widening event on the eventual
    # rename).
    if _stat.S_ISREG(st.st_mode):
        return _stat.S_IMODE(st.st_mode)
    return 0o644


def write_text_atomically(
    path: Union[str, Path],
    content: str,
    *,
    encoding: str = "utf-8",
    tmp_prefix: str = ".atomic-",
    mode: Optional[int] = None,
) -> None:
    """Write ``content`` (str) to ``path`` atomically.

    Thin wrapper over :func:`write_bytes_atomically`; encodes to
    bytes and delegates. See module docstring for full semantics.

    ``path.parent`` is created if missing.

    ``mode`` semantics: see :func:`write_bytes_atomically`.
    """
    write_bytes_atomically(
        path,
        content.encode(encoding),
        tmp_prefix=tmp_prefix,
        mode=mode,
    )


def write_bytes_atomically(
    path: Union[str, Path],
    content: bytes,
    *,
    tmp_prefix: str = ".atomic-",
    mode: Optional[int] = None,
) -> None:
    """Write ``content`` (bytes) to ``path`` atomically.

    See module docstring for full semantics. Binary variant so
    callers writing JSONL / images / archives don't have to double-
    encode.

    ``path.parent`` is created if missing.

    ``mode`` (optional): when set to an integer in ``0o000..0o777``,
    applied via ``os.fchmod`` on the tempfile BEFORE the rename so
    the atomic rename installs a file that already has the requested
    permissions — no window where the file exists at default perms
    before a chmod tightens them. Callers with security-sensitive
    writes (credentials, session tokens, per-user state) should pass
    ``mode=0o600``. Setuid / setgid / sticky bits are rejected —
    callers that genuinely need those bits must chmod explicitly.

    When ``mode`` is None (default), preserves existing perms if the
    destination is a regular file (guards the operator-chmod case),
    else uses 0o644.
    """
    _validate_mode(mode)
    path = Path(path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    effective_mode = _resolve_effective_mode(path, mode)

    # Tempfile name = prefix + basename + PID + TID + random suffix.
    # Each component blocks a specific attack / collision:
    #   - PID: two processes on shared FS don't collide
    #   - TID: two threads in same process don't collide
    #   - random: an attacker who knows PID + TID (via /proc, ps)
    #     still can't predict the full path to pre-create a squat
    #     file. Combined with O_EXCL + O_NOFOLLOW below, symlink-
    #     through and pre-created-file attacks fail loud.
    tid = threading.get_ident()
    rand = secrets.token_hex(4)
    tmp = path.with_name(
        f"{tmp_prefix}{path.name}.{os.getpid()}.{tid}.{rand}.tmp",
    )

    # O_EXCL: refuse if tempfile already exists (attacker squat, or
    # stale from a crashed prior invocation — either way the operator
    # should see and clean up rather than us silently overwriting).
    # O_NOFOLLOW: refuse if tempfile is a symlink. Defence-in-depth
    # against a squatter who predicts the tempfile name.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)

    fd = os.open(tmp, flags, effective_mode)
    try:
        try:
            # O_CREAT + mode gets umask-adjusted. Explicit fchmod
            # bypasses umask so the caller's requested mode WINS
            # regardless of the process's umask. On the preserve-
            # existing path this is a no-op.
            os.fchmod(fd, effective_mode)
        except (OSError, AttributeError):
            # Windows + some mounts don't honour fchmod — the
            # O_CREAT mode argument was already best-effort.
            pass
        try:
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        # Atomic rename. Same-FS on POSIX is atomic by spec; the
        # tempfile sits in the same directory to guarantee that.
        # Cross-FS raises EXDEV — but tmp lives in path.parent so
        # this is unreachable in practice.
        os.replace(tmp, path)
        # Best-effort durability: fsync the parent directory so the
        # rename survives a power loss. Windows + some mounts don't
        # support directory fsync — silent fallback is fine.
        try:
            dir_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except BaseException:
        # Catch BaseException (which includes KeyboardInterrupt)
        # explicitly — that's the exact scenario a torn write would
        # otherwise happen in. Best-effort clean up of the tempfile.
        # The fd was already closed inside the inner try/finally on
        # success paths; on the O_EXCL failure path the fd never
        # existed. On mid-write failure the finally block above
        # closed the fd before we got here.
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


__all__ = ["write_text_atomically", "write_bytes_atomically"]
