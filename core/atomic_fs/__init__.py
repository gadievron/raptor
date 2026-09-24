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
unearned for outputs that just get re-run on failure. Those writers
use the EXCLUSIVE-create family below instead:

  * ``open_exclusive_artifact`` / ``write_new_bytes`` /
    ``write_new_text`` — ``O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC``
    creation of a NEW artifact. The artifact's directory is (or was)
    inside a sandboxed child's write grant, so anything already
    occupying the destination name — a planted symlink aimed at a
    victim file, a reader-less FIFO, a pre-created file — makes the
    open fail closed instead of following/truncating/blocking.
    ``replace=True`` adds an lstat-honest pre-unlink for writers that
    own the name and legitimately re-emit it (campaign logs, staged
    seeds): ``Path.unlink`` removes a planted symlink ITSELF (never
    its target), and the O_EXCL create still fails loud if something
    reappears in the unlink→open window.
  * ``open_hardened_append`` — the trail-append open shape
    (``O_APPEND | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`` + post-open
    fstat S_ISREG refusal) for callers that keep a long-lived append
    handle and therefore cannot route through
    ``core.json.append_jsonl``'s one-shot write.

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

Client-locality caveat (WSL drvfs/9p, no behaviour change): on a
Windows-interop mount the ``os.replace`` commit is executed by the
9p server, and readers within the same distro (one client) keep the
full old-bytes-or-new-bytes guarantee exactly as on a local
filesystem — this covers every consumer above (annotation saves,
``save_json`` metadata writes, the JSON cache's puts) when writer
and reader share the distro. Readers on ANOTHER client (Windows
side, another distro) go through their own attribute/dentry caches:
they still never see a torn file, but can keep observing the
pre-replace content for the cache window after the commit, and the
fsync durability legs are delegated to the 9p server. Placement
guidance lives in docs/wsl.md.
"""

from __future__ import annotations

import os
import secrets
import stat as _stat
import threading
from pathlib import Path


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


# Perm mask: only the low 9 bits are legal via ``mode=``. Rejects
# setuid (0o4000), setgid (0o2000), sticky (0o1000). None of the
# durability-critical consumers should be shipping files with those
# bits set; requiring an explicit path (chmod after the write) forces
# an operator to think about it.
_MODE_MASK = 0o777


def _validate_mode(mode: int | None) -> None:
    """Reject ``mode`` values outside 0o000..0o777.

    Raises ``ValueError`` on anything not representable as a plain
    POSIX file mode. Explicit rejection beats silent masking: a caller
    passing ``mode=0o4755`` is either confused or trying to install a
    setuid file — either way we want to fail loud, not paper over it.
    """
    if mode is None:
        return
    if not isinstance(mode, int):
        msg = f"mode must be int (0o000..0o777), got {type(mode).__name__}"
        raise ValueError(msg)
    if not (0 <= mode <= _MODE_MASK):
        msg = f"mode must be in 0o000..0o777, got 0o{mode:o}"
        raise ValueError(msg)


def _resolve_effective_mode(
    path: Path,
    mode: int | None,
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
    path: str | Path,
    content: str,
    *,
    encoding: str = "utf-8",
    tmp_prefix: str = ".atomic-",
    mode: int | None = None,
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
    path: str | Path,
    content: bytes,
    *,
    tmp_prefix: str = ".atomic-",
    mode: int | None = None,
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
        # The close lives in a finally that starts IMMEDIATELY after
        # the open succeeds, so every exception path — including a
        # BaseException raised inside the fchmod window — closes the
        # fd before the outer handler unlinks the tempfile.
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
            # ``os.write`` may return a SHORT count (interrupted by a
            # signal after partial progress, filesystem-specific
            # limits on single-call sizes). Pre-fix the single call
            # ignored the return value: a positive short write then
            # fsync'd and ``os.replace``'d a TRUNCATED file as
            # committed — the exact torn-write the primitive exists
            # to prevent. Loop until every byte is written; a
            # zero-progress write raises instead of spinning.
            view = memoryview(content)
            written = 0
            while written < len(view):
                n = os.write(fd, view[written:])
                if n <= 0:
                    raise OSError(
                        f"short write to {tmp}: os.write returned {n}",
                    )
                written += n
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
        # The fd is always closed before we get here: the inner
        # try/finally spans everything from the successful os.open
        # (fchmod included) through the fsync, and on the O_EXCL
        # failure path the fd never existed.
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def open_exclusive_artifact(
    path: str | Path,
    *,
    mode: int = 0o644,
    replace: bool = False,
) -> int:
    """Exclusively create the NEW artifact at *path*; return the fd.

    ``O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC``: anything
    already occupying the destination — a planted symlink (even a
    dangling one, which passes ``exists() == False``), a FIFO, a
    pre-created file — fails the open with ``OSError``
    (``FileExistsError`` for an occupied name) instead of being
    followed or truncated. Generalises the seed-writer idiom the
    corpus profiler carried locally.

    ``replace=True``: for writers that OWN the name and legitimately
    re-emit it (campaign logs, staged seeds, generated scripts) —
    pre-unlink with lstat honesty (``Path.unlink`` removes a planted
    symlink/FIFO ITSELF, never what it points at; a directory at the
    name still raises), then the O_EXCL create fails loud if anything
    reappears in the unlink→open window.

    ``mode`` is validated like the atomic writers' (0o000..0o777, no
    setuid/setgid/sticky) and enforced via best-effort ``fchmod`` so
    a caller-requested mode (0o600 secrets, 0o755 scripts) wins over
    the process umask.

    The caller owns the returned fd (``os.fdopen`` or ``os.close``).
    """
    _validate_mode(mode)
    p = Path(path)
    if replace:
        p.unlink(missing_ok=True)
    fd = os.open(
        str(p),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
        mode,
    )
    try:
        os.fchmod(fd, mode)
    except (OSError, AttributeError):
        # Windows + some mounts don't honour fchmod — the O_CREAT
        # mode argument was already best-effort.
        pass
    return fd


def write_new_bytes(
    path: str | Path,
    content: bytes,
    *,
    mode: int = 0o644,
    replace: bool = False,
) -> None:
    """Write *content* to a NEW artifact at *path* via
    :func:`open_exclusive_artifact` (see there for the refusal and
    ``replace`` semantics). Raises ``OSError`` on refusal or write
    failure; no tempfile, no fsync — for regeneratable outputs where
    the atomic writers' durability cost is unearned."""
    fd = open_exclusive_artifact(path, mode=mode, replace=replace)
    try:
        view = memoryview(content)
        written = 0
        while written < len(view):
            n = os.write(fd, view[written:])
            if n <= 0:
                raise OSError(
                    f"short write to {path}: os.write returned {n}",
                )
            written += n
    finally:
        os.close(fd)


def write_new_text(
    path: str | Path,
    content: str,
    *,
    encoding: str = "utf-8",
    mode: int = 0o644,
    replace: bool = False,
) -> None:
    """Text variant of :func:`write_new_bytes`."""
    write_new_bytes(
        path, content.encode(encoding), mode=mode, replace=replace,
    )


def open_hardened_append(path: str | Path, *, mode: int = 0o644) -> int:
    """Open *path* for appending with the hardened trail shape; return
    the fd.

    ``O_NOFOLLOW`` refuses a planted symlink (ELOOP); ``O_NONBLOCK``
    makes a planted reader-less FIFO fail fast (ENXIO) instead of
    blocking the writer forever; the post-open ``fstat`` S_ISREG
    check refuses everything else non-regular (a FIFO that has a
    reader, a device). Same flags as ``core.json.append_jsonl`` — use
    this when the caller keeps a persistent append handle (streamed
    event trails) instead of appending one record per call.

    Raises ``OSError`` on refusal. The caller owns the returned fd.
    """
    _validate_mode(mode)
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_APPEND
        | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK
    )
    fd = os.open(str(path), flags, mode)
    try:
        if not _stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(
                f"refusing to append to {path}: not a regular file "
                "(planted FIFO/device at the trail path?)",
            )
    except BaseException:
        os.close(fd)
        raise
    return fd


__all__ = [
    "open_exclusive_artifact",
    "open_hardened_append",
    "write_bytes_atomically",
    "write_new_bytes",
    "write_new_text",
    "write_text_atomically",
]
