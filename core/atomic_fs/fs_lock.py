"""Shared cross-process lock for load → merge → write artifact windows.

THE flock idiom RAPTOR's durable JSON stores use, hoisted so new
writers stop re-implementing it (the spec store, the coverage store,
and the study promotion each carry a local copy; new call sites route
here). Contract, matching those siblings:

- lock a sibling ``<artifact>.lock`` file, never the artifact itself —
  the artifact is atomically replaced on save, and flocking a replaced
  inode splits lockers;
- hold the lock across the WHOLE load → merge → write cycle;
- ``O_NOFOLLOW``: the lock file may live in a directory broader write
  grants reach — a planted symlink must not steer the flock to an
  attacker-chosen path. A refused open degrades to the unlocked path
  with a loud warning rather than failing the (best-effort) writer;
- ``O_NONBLOCK`` plus the post-open ``fstat`` regularity refusal: a
  planted reader-less FIFO at the lock path would otherwise block the
  writer forever on the bare ``O_WRONLY`` open, and a FIFO that has a
  reader would flock a non-regular inode. Both degrade to the same
  loud unlocked path (same discipline as
  ``core.run.metadata``'s metadata lock);
- foreign-uid refusal: a PRE-EXISTING lock file owned by another uid
  is never adopted. Any process that can create the predictable
  ``.lock`` sibling (a sandboxed child with a write grant over the
  artifact dir) could otherwise pre-create it, hold ``LOCK_EX``, and
  stall every cooperating writer indefinitely — the open succeeds, so
  the tamper-degrade arm never fired. A foreign owner degrades to the
  same loud unlocked path as a planted symlink or FIFO;
- bounded acquisition: the flock is taken ``LOCK_NB``-first; on
  contention the waiter says so ONCE (naming the subject and lock
  path), then polls up to a generous deadline. A wedged or hostile
  holder can no longer stall a writer silently and unboundedly — on
  expiry the writer degrades to the loud unlocked path (the same
  best-effort disposition every other lock-unavailable shape takes);
- degrade to a no-op without ``fcntl`` (non-POSIX);
- the lock file is deliberately never unlinked — unlink-after-unlock
  races split lockers across two inodes. Its only content is the last
  acquirer's pid stamp (advisory, possibly stale — see
  :func:`stamp_lock_holder`).

Client-locality caveat (WSL drvfs/9p, no behaviour change): on a
Windows-interop mount, ``flock`` is implemented by the 9p client —
it serialises processes within one distro (one client) exactly as on
a local filesystem, but grants no exclusion against Windows-side
writers or other WSL distros mounting the same drive. Artifacts on
such mounts keep same-distro correctness and silently lose the
cross-context guarantee; placement guidance lives in docs/wsl.md.
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import stat as _stat
import time
from collections.abc import Iterator
from pathlib import Path

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:  # non-POSIX (Windows) — locks degrade to no-ops
    _HAS_FCNTL = False

logger = logging.getLogger(__name__)

# How long a contended acquire waits before giving up. Not lower: a
# legitimate holder spans a whole load → merge → write window, and the
# longest cooperating holds (journal compaction sweeping a large shard
# set on slow disk) run for tens of seconds — a tighter deadline would
# push writers onto the degraded/refused path exactly when
# serialisation matters most. Not higher: this deadline is the ONLY
# bound between a wedged or hostile holder and a stalled writer; a
# minute already dwarfs every legitimate hold, and each additional
# minute is pure hostage time with no correctness gain.
_ACQUIRE_DEADLINE_S: float = 60.0

# Retry cadence while waiting. Not lower: sub-100ms polling burns CPU
# re-issuing flock() with no latency benefit at the multi-second hold
# scales the deadline anticipates. Not higher: the poll interval is
# the worst-case extra latency EVERY contended acquire pays after the
# holder releases — half a second would be a visible stall on the
# interactive paths (annotation saves, project mutations) that contend
# only briefly.
_ACQUIRE_POLL_S: float = 0.1

# flock(LOCK_NB) contention errnos. EWOULDBLOCK is the documented one;
# EAGAIN aliases it on Linux and EACCES is the POSIX-permitted variant
# some locking layers return.
_CONTENTION_ERRNOS = (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK)


def validate_lock_fd(fd: int, lock_path: Path) -> None:
    """Refuse a lock inode this process must not adopt.

    Raises ``OSError`` when the opened fd is not a regular file (a
    planted FIFO that had a reader, a device node) or when a
    PRE-EXISTING lock file belongs to a different uid. The predictable
    ``.lock`` sibling name makes pre-creation trivial for anything
    with a write grant over the artifact dir; adopting a foreign-uid
    file hands that writer a standing hold over every cooperating
    writer. Callers route the raise to their existing tamper-degrade
    (or refuse) arm.
    """
    st = os.fstat(fd)
    if not _stat.S_ISREG(st.st_mode):
        raise OSError(
            f"lock path {lock_path} is not a regular file")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:  # non-POSIX: no uid to compare
        return
    euid = geteuid()
    if st.st_uid != euid:
        raise OSError(
            f"lock file {lock_path} is owned by uid {st.st_uid}, not "
            f"this process's effective uid {euid} — refusing to adopt "
            "a foreign lock file"
        )


def stamp_lock_holder(fd: int) -> None:
    """Best-effort: record this process's pid as the lock file's only
    content, for the contention diagnostic.

    Advisory and race-honest by construction: the stamp is written
    AFTER acquisition and survives release (flock drops on close, the
    bytes stay), so a reader must treat it as "last acquirer, possibly
    stale" — never as proof of a live holder. Failures are swallowed
    (read-only fd, ENOSPC): the stamp is a diagnostic, never part of
    the exclusion contract. Only ever called on sidecar lock fds whose
    content is disposable — NEVER on data-file flocks (O_APPEND
    journals), where a write would corrupt the store.

    Written IN PLACE, truncating only when the old content is longer:
    this runs on every acquisition, and a truncate-to-zero before each
    rewrite trips ext4's replace-via-truncate heuristic — a forced
    data writeback per open → truncate → write → close cycle (~1ms
    measured) that would tax every UNCONTENDED acquire on the
    interactive paths. An equal-or-shorter old stamp is fully
    overwritten by ``pwrite`` at offset 0; only a longer one (a wider
    previous pid, hostile stuffing) pays the truncate.
    """
    with contextlib.suppress(OSError):
        stamp = b"%d\n" % os.getpid()
        if os.fstat(fd).st_size > len(stamp):
            os.ftruncate(fd, 0)
        os.pwrite(fd, stamp, 0)


def _holder_hint(lock_path: Path) -> str:
    """Parse the advisory pid stamp for the contention warning.

    Strictly an integer parse of a HARDENED, CAPPED read — the lock
    path sits in directories hostile writers can reach, and it can be
    swapped between the waiter's open and its first contention, so the
    hint read must survive the same shapes as the lock open itself:

    - a planted FIFO must not wedge the read (a bare ``Path.read_bytes``
      open blocks on a reader-less FIFO — before the deadline loop even
      starts, defeating the bounded-wait contract);
    - a stuffed lock file must not be slurped whole (``read_bytes()``
      reads EVERYTHING before any slice — an attacker-sized
      allocation per contended acquire);
    - nothing but a decimal pid is ever echoed into the log.

    ``core.source.read_text_capped`` provides exactly that
    (``O_NOFOLLOW`` / ``O_NONBLOCK`` / regularity refusal / capped
    bytes). Every failure shape degrades to "no hint".
    """
    from core.source import read_text_capped  # lazy, matching peers

    # 64 chars: a pid stamp is "%d\n" (<= 21 chars even for a 64-bit
    # pid); the headroom tolerates whitespace padding while anything
    # larger is not a stamp and must not parse.
    got = read_text_capped(lock_path, 64)
    if got is None:
        return ""
    text, truncated = got
    if truncated:
        return ""
    try:
        pid = int(text.strip())
    except ValueError:
        return ""
    if pid <= 0:
        return ""
    return f" (lock file last stamped by pid {pid}; may be stale)"


def _try_flock_nb(fd: int) -> bool:
    """One non-blocking LOCK_EX attempt; ``False`` means contended."""
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in _CONTENTION_ERRNOS:
            return False
        raise
    return True


def acquire_flock_bounded(
    fd: int,
    lock_path: Path,
    *,
    subject: str,
    stamp: bool = False,
    deadline_s: float | None = None,
    poll_s: float | None = None,
    expiry_note: str | None = None,
) -> bool:
    """Take ``LOCK_EX`` on *fd* without ever waiting silently or
    unboundedly.

    Non-blocking first attempt; on contention emit ONE warning naming
    *subject* and *lock_path* (plus the advisory holder stamp when one
    parses), then poll until the deadline. Returns ``True`` once the
    lock is held, ``False`` on expiry — the caller decides whether
    expiry degrades to its unlocked path or raises. With ``stamp``,
    the acquirer's pid is written into the (sidecar) lock file; leave
    it ``False`` for data-file flocks.

    Expiry is LOUD here, not in the caller: a waiter that announced
    "waiting up to Ns" and then went quiet leaves the operator with a
    60s-old promise and no outcome, and caller-side raises can be
    swallowed by broad handlers on best-effort paths. *expiry_note*
    states the consequence in that warning ("row NOT appended",
    "proceeding WITHOUT cross-process lock — ..."); the default is a
    generic give-up note.

    ``deadline_s`` / ``poll_s`` default to the module constants at
    call time.
    """
    if deadline_s is None:
        deadline_s = _ACQUIRE_DEADLINE_S
    if poll_s is None:
        poll_s = _ACQUIRE_POLL_S
    if _try_flock_nb(fd):
        if stamp:
            stamp_lock_holder(fd)
        return True
    # The stamp hint is read only where stamping happens (sidecar lock
    # fds). For data-file flocks *lock_path* IS the data file: it never
    # carries a stamp, and reading it for a hint would touch
    # shard-sized content on every contended acquire.
    hint = _holder_hint(lock_path) if stamp else ""
    logger.warning(
        "%s lock %s: held by another process%s; waiting up to %.0fs",
        subject, lock_path, hint, deadline_s,
    )
    deadline = time.monotonic() + deadline_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.warning(
                "%s lock %s: still held after %.0fs — %s",
                subject, lock_path, deadline_s,
                expiry_note or "giving up (bounded wait expired)",
            )
            return False
        time.sleep(min(poll_s, remaining))
        if _try_flock_nb(fd):
            if stamp:
                stamp_lock_holder(fd)
            return True


@contextlib.contextmanager
def sidecar_flock(
    lock_path: Path,
    *,
    subject: str = "artifact",
    create_parent: bool = True,
) -> Iterator[None]:
    """Exclusive cross-process flock on an explicit sidecar lock file.

    The full hoisted idiom for callers whose lock file is not the
    plain ``<artifact>.lock`` sibling (:func:`artifact_lock` wraps
    this for those that are): hardened open, foreign-uid refusal,
    bounded LOCK_NB-first acquisition, pid stamp. Every
    lock-unavailable shape — uncreatable, tamper-shaped, foreign-uid,
    or held past the deadline — degrades to the loud unlocked path
    rather than failing the (best-effort) writer.

    *subject* names the guarded resource in the warnings.
    ``create_parent=False`` preserves callers whose missing parent dir
    must degrade rather than be created.
    """
    if not _HAS_FCNTL:
        yield
        return
    flags = (
        os.O_WRONLY | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = None
    try:
        if create_parent:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), flags, 0o600)
        validate_lock_fd(fd, lock_path)
    except OSError as exc:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        logger.warning(
            "%s lock %s: refusing to open (%s); proceeding WITHOUT "
            "cross-process lock — concurrent writers may drop each "
            "other's contributions; investigate a planted symlink, "
            "FIFO or foreign-uid file at that path", subject, lock_path,
            exc,
        )
        yield
        return
    try:
        if not acquire_flock_bounded(
                fd, lock_path, subject=subject, stamp=True,
                expiry_note=(
                    "proceeding WITHOUT cross-process lock — "
                    "concurrent writers may drop each other's "
                    "contributions; investigate a wedged or hostile "
                    "holder of that lock file"
                )):
            yield
            return
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextlib.contextmanager
def artifact_lock(
    artifact: Path,
    *,
    subject: str = "artifact",
    create_parent: bool = True,
) -> Iterator[None]:
    """Exclusive cross-process lock over *artifact*'s read-modify-write
    window (flocks the sibling ``<artifact>.lock``).

    *subject* names the guarded resource in the degrade warning.
    ``create_parent=False`` preserves callers whose missing parent dir
    must degrade to the loud unlocked path rather than be created —
    conjuring a directory the owner deliberately removed is a side
    effect the lock has no business having.
    """
    lock_path = artifact.with_suffix(artifact.suffix + ".lock")
    with sidecar_flock(lock_path, subject=subject,
                       create_parent=create_parent):
        yield
