"""Tamper-resistant placement for sandbox enforcement evidence.

Two problems share one root cause — evidence about the sandboxed
process was stored where the sandboxed process could touch it:

* The tracer's ``.sandbox-denials.jsonl`` / ``.sandbox-observe.jsonl``
  (and ``summary.record_denial``'s output) used to land directly in
  ``audit_run_dir``, which typically IS the sandbox output dir — the
  one directory that is Landlock-writable and rw-bind-mounted for the
  target. The target could rewrite, truncate, or pre-create the log.
* The observe-mode nonce used to be parked in a
  ``/tmp/raptor-audit-cfg-*.json`` tempfile. On the namespace-less
  Landlock-only path, /tmp is shared and readable — the target could
  glob the path, read the nonce, and mint records the parser trusts.

This module provides the two replacement mechanisms:

1. ``EvidenceFile`` — evidence JSONL lives in ``<run_dir>/.audit/``,
   a directory the parent creates 0700 and that is excluded from the
   child's writable view on every backend that can express the
   exclusion (mount-ns: shadowed by a read-only tmpfs; macOS: seatbelt
   deny rule; Landlock: not granted whenever the evidence dir is not
   beneath a granted writable path). The file is created ``O_EXCL`` at
   sandbox start; the creating process holds the fd and all appends go
   through that fd (the ptrace tracer inherits the same open file
   description across its exec). The inode is recorded at creation and
   re-checked at finalisation — a swapped file is detected and warned
   about loudly even where the exclusion could not be enforced (e.g.
   Landlock-only hosts where the run dir is itself a writable grant:
   Landlock allow-rules are subtree-recursive with no subtraction, so
   a ``.audit/`` dir beneath a granted dir cannot be carved out).

2. ``anonymous_fd`` / ``fd_path`` — config (and the nonce inside it)
   is handed to the tracer as an anonymous file descriptor: a memfd on
   Linux, an unlinked temp file elsewhere. The fd is close-on-exec by
   default; the spawn code clears close-on-exec only in the tracer
   child's post-fork branch — never for the target's exec — and passes
   ``/proc/self/fd/N`` (Linux) or ``/dev/fd/N`` (macOS) in the
   tracer's argv. The nonce therefore never exists at a filesystem
   path the target can name. The tracer closes the inherited fd as
   soon as the config is parsed (before the target is unblocked) so
   the ``/proc/<tracer-pid>/fd/N`` reflection of the fd disappears
   before untrusted code runs; the tracer additionally sets
   PR_SET_DUMPABLE=0 so same-UID processes cannot traverse its
   ``/proc/<pid>/fd`` at all.

Back-compat: readers should use :func:`resolve_read_path`, which
prefers the new ``<run_dir>/.audit/<name>`` location and falls back to
the legacy ``<run_dir>/<name>`` spot for artifacts produced by older
runs (kept for one release).
"""

from __future__ import annotations

import contextlib
import errno
from core.json import dumps_artifact
from core.security.capped_read import path_may_exist
from core.security.log_sanitisation import sanitise_for_terminal
import logging
import os
import stat as _stat
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Subdirectory of the run dir that holds enforcement evidence. The
# leading dot keeps it out of operator-facing listings; the name is
# load-bearing for the mount-ns shadowing (mount_ns.py) and the macOS
# seatbelt deny rule (seatbelt.build_profile) — all three must agree.
AUDIT_SUBDIR = ".audit"


def _unique_evidence_object(fields: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous objects before duplicate members are overwritten."""
    record: dict[str, Any] = {}
    for field, value in fields:
        if field in record:
            raise ValueError("duplicate field in evidence object")
        record[field] = value
    return record


def audit_dir_path(run_dir) -> Path:
    """``<run_dir>/.audit`` — where evidence JSONL files live."""
    return Path(run_dir) / AUDIT_SUBDIR


def evidence_write_path(run_dir, filename: str) -> Path:
    """Canonical (new) location for an evidence JSONL. Writers always
    target this path; readers go through :func:`resolve_read_path`."""
    return audit_dir_path(run_dir) / filename


def legacy_read_path(run_dir, filename: str) -> Path:
    """Pre-relocation location (``<run_dir>/<filename>``)."""
    return Path(run_dir) / filename


def resolve_read_path(run_dir, filename: str) -> Path:
    """Pick the evidence path for READING with back-compat.

    Prefers ``<run_dir>/.audit/<filename>``; falls back to the legacy
    ``<run_dir>/<filename>`` when only the old location exists (runs
    produced by older versions). When neither exists, returns the new
    location so error messages point at the canonical path. Dangling
    symlinks count as present entries so no-follow readers can refuse and
    report them instead of silently falling back to older evidence.
    Metadata errors also retain the candidate for that refusal path.
    """
    new = evidence_write_path(run_dir, filename)
    if path_may_exist(new):
        return new
    old = legacy_read_path(run_dir, filename)
    if path_may_exist(old):
        return old
    return new


def ensure_audit_dirfd(run_dir) -> int:
    """Create ``<run_dir>/.audit`` mode 0700 if needed and return an
    ``O_DIRECTORY | O_NOFOLLOW`` fd pinning its identity.

    Refuses a symlink (ELOOP) or non-directory (ENOTDIR) at the
    ``.audit`` path — a pre-planted symlink would redirect evidence
    into an attacker-chosen directory. Returning the fd (rather than
    validating by pathname and letting callers re-resolve the path
    later) closes the check→use race: a hostile same-UID process
    with run-dir write access could otherwise swap an intermediate
    component between our validation and the caller's open. Callers
    open evidence files RELATIVE to this fd (``dir_fd=``) so every
    open lands in the directory that was actually validated. Existing
    directories must be owned by this user and not group/other-writable;
    read/execute permission bits are preserved. Caller owns the fd and
    must close it.
    """
    d = audit_dir_path(run_dir)
    try:
        os.mkdir(d, 0o700)
    except FileExistsError:
        pass
    # O_DIRECTORY refuses files/FIFOs (ENOTDIR), O_NOFOLLOW refuses a
    # symlink in the final component (ELOOP/ENOTDIR). The fstat is on
    # the fd, so the object checked is the object we hold.
    try:
        fd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                     | os.O_CLOEXEC)
    except OSError as e:
        raise OSError(
            f"evidence dir {d} failed the O_DIRECTORY|O_NOFOLLOW open "
            f"({e.strerror}) — symlink or file planted? refusing to "
            f"use it"
        ) from None
    try:
        st = os.fstat(fd)
        if not _stat.S_ISDIR(st.st_mode):
            raise OSError(
                f"evidence dir {d} is not a directory "
                f"(symlink or file planted?) — refusing to use it"
            )
        if st.st_uid != os.getuid() or st.st_mode & 0o022:
            raise OSError(
                f"evidence dir {d} failed ownership/permissions validation "
                f"(mode={oct(st.st_mode)}, uid={st.st_uid}) "
                f"— refusing to use it"
            )
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise
    return fd


def ensure_audit_dir(run_dir) -> Path:
    """Create ``<run_dir>/.audit`` mode 0700 if needed; return it.

    Pathname-returning convenience wrapper over
    :func:`ensure_audit_dirfd` for callers that only need the
    location (e.g. to interpolate into a Seatbelt profile). Callers
    that go on to OPEN files in the directory must use
    :func:`ensure_audit_dirfd` + ``dir_fd=`` instead — a returned
    pathname re-resolves on every use and is raceable.
    """
    fd = ensure_audit_dirfd(run_dir)
    os.close(fd)
    return audit_dir_path(run_dir)


def _safe_evidence_file_metadata(st: os.stat_result) -> bool:
    """The same file-safety floor applies at append-open and verification."""
    return (_stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
            and st.st_nlink == 1 and not (st.st_mode & 0o022))


class EvidenceFile:
    """A parent-held, append-only evidence JSONL.

    Created with ``O_EXCL`` (or validated append when a previous
    sandbox call in the same run already created it), fd held for the
    file's lifetime, inode recorded at open and verified at
    finalisation. All appends go through the held fd — writers that
    inherit the fd (the ptrace tracer) share the same open file
    description, so a rename/unlink of the path cannot redirect their
    appends. An instance lock coordinates parent-thread writes and
    closure; tracer processes continue using the inherited raw fd.
    """

    def __init__(self, fd: int, path: Path, st: os.stat_result) -> None:
        self.fd = fd
        self.path = path
        self._created_dev = st.st_dev
        self._created_ino = st.st_ino
        self._minimum_size = st.st_size
        self._closed = False
        self._fd_released = False
        self._close_result = False
        self._io_lock = threading.RLock()
        self._needs_resync = False

    @classmethod
    def open(cls, run_dir, filename: str) -> EvidenceFile:
        """Create (or validate-and-append-to) the evidence file.

        First choice is ``O_CREAT|O_EXCL`` — defeats pre-created files
        and symlinks planted before sandbox start. When the file
        already exists (a prior sandbox call in the same run created
        it), it is re-opened with ``O_NONBLOCK`` and accepted only if
        it is a regular, non-hard-linked file owned by us with no
        group/other write bits. ``O_NONBLOCK`` on the re-open is the
        FIFO defence: a planted FIFO with no reader fails the open
        with ENXIO instead of blocking the parent until a hostile
        reader chooses to appear, and a FIFO WITH a reader passes the
        open but fails the ``S_ISREG`` check — either way the fstat
        runs on the object we actually hold, never on a pathname.
        The flag is cleared after validation (it is meaningless on
        regular files, but inheritors of the fd shouldn't see a
        surprising flag state).

        Both paths validate safety metadata on the acquired descriptor
        before returning it, including files just created with O_EXCL.

        Both opens are RELATIVE to the validated ``.audit`` dirfd
        (:func:`ensure_audit_dirfd`), so a raced swap of an
        intermediate path component between directory validation and
        file open cannot redirect evidence creation.
        """
        if os.sep in filename or filename in (".", ".."):
            raise ValueError(
                f"evidence filename must be a bare name, got {filename!r}")
        flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = None
        dirfd = ensure_audit_dirfd(run_dir)
        try:
            path = evidence_write_path(run_dir, filename)
            reopened = False
            try:
                fd = os.open(filename, flags | os.O_CREAT | os.O_EXCL,
                             0o600, dir_fd=dirfd)
            except FileExistsError:
                fd = os.open(filename, flags | os.O_NONBLOCK,
                             dir_fd=dirfd)
                reopened = True
            # Exclusive creation does not freeze metadata: validate the
            # descriptor on both paths before any append can be attempted.
            st = os.fstat(fd)
            if not _safe_evidence_file_metadata(st):
                raise OSError(
                    f"evidence file {path} failed validation "
                    f"(mode={oct(st.st_mode)}, uid={st.st_uid}, "
                    f"nlink={st.st_nlink}) — refusing to append"
                ) from None
            if reopened:
                # Clear O_NONBLOCK now that we know it's a regular
                # file (no-op semantically; keeps the fd's flag state
                # unsurprising for inheritors like the tracer).
                import fcntl as _fcntl
                fl = _fcntl.fcntl(fd, _fcntl.F_GETFL)
                _fcntl.fcntl(fd, _fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
            return cls(fd, path, st)
        except BaseException:
            # Ownership transfers only after construction succeeds.
            # Metadata/flag setup failures must release the file as
            # well as the directory fd, preserving the original error.
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
            raise
        finally:
            with contextlib.suppress(OSError):
                os.close(dirfd)

    def write_line(self, line: str) -> bool:
        """Append one JSONL line through the held fd. Returns True on
        success, False on encoding or I/O failure. Each record uses
        one append write; fragments are never retried. After a failed
        append, a leading newline protects the next record from being
        joined onto an incomplete predecessor."""
        if self._closed:
            return False
        try:
            data = line.encode("utf-8")
            with self._io_lock:
                # Encoding and thread scheduling may have allowed close()
                # to release this descriptor since the fast check above.
                if self._closed:
                    return False
                if self._needs_resync:
                    data = b"\n" + data
                # Set this before I/O: cancellation after a short write
                # returns must not bypass the recovery-state update.
                self._needs_resync = True
                written = os.write(self.fd, data)
                self._minimum_size += max(written, 0)
                if written == len(data):
                    self._needs_resync = False
            if written != len(data):
                # Do not retry fragments: another appender may have
                # written a record after this partial write.
                logger.warning(
                    "evidence append incomplete for %s: wrote %s of %s bytes",
                    sanitise_for_terminal(str(self.path)), written, len(data),
                )
                return False
            return True
        except (OSError, UnicodeError) as exc:
            logger.warning(
                "evidence append failed for %s: %s: %s",
                sanitise_for_terminal(str(self.path)),
                sanitise_for_terminal(type(exc).__name__, max_len=64),
                sanitise_for_terminal(str(exc)),
            )
            return False

    def write_record(self, record: dict) -> bool:
        """JSON-encode ``record`` and append it as one line."""
        try:
            line = dumps_artifact(record, indent=None, ensure_ascii=True) + "\n"
        except (TypeError, ValueError, RecursionError):
            logger.warning("evidence record not serialisable", exc_info=True)
            return False
        return self.write_line(line)

    def verify(self) -> bool:
        """Check identity, safety metadata and known append progress.

        The opening size plus this handle's writes is a persistent floor;
        the shared offset also covers raw descriptor inheritors' writes.
        This cannot detect rewrites or regrowth back to those bounds.
        Mismatch, truncation, missing files, and descriptor inspection
        failures emit a loud warning and return False. Bytes at this path
        can no longer be trusted as the complete original evidence.
        After close, return its cached result without further path/fd I/O.
        """
        with self._io_lock:
            if self._fd_released:
                return self._close_result
            return self._verify_locked()

    def _verify_locked(self) -> bool:
        try:
            st = os.stat(self.path, follow_symlinks=False)
        except OSError:
            logger.warning(
                "SANDBOX EVIDENCE TAMPER SUSPECTED: evidence file %s "
                "vanished during the run (created dev=%s ino=%s). "
                "Records appended via the held fd are intact in the "
                "original inode but the on-disk path was removed.",
                sanitise_for_terminal(str(self.path)), self._created_dev, self._created_ino,
            )
            return False
        if (st.st_dev, st.st_ino) != (self._created_dev, self._created_ino):
            logger.warning(
                "SANDBOX EVIDENCE TAMPER SUSPECTED: evidence file %s "
                "was swapped during the run (created dev=%s ino=%s, "
                "now dev=%s ino=%s). Do not trust the file at this "
                "path; treat this run's evidence as compromised.",
                sanitise_for_terminal(str(self.path)), self._created_dev, self._created_ino,
                st.st_dev, st.st_ino,
            )
            return False
        try:
            # Read the offset before size: concurrent raw-fd appenders may
            # grow the file, but cannot manufacture a false shrink result.
            written_end = os.lseek(self.fd, 0, os.SEEK_CUR)
            held = os.fstat(self.fd)
            size = held.st_size
        except OSError as exc:
            logger.warning(
                "SANDBOX EVIDENCE TAMPER SUSPECTED: cannot verify the "
                "held evidence descriptor for %s: %s: %s",
                sanitise_for_terminal(str(self.path)),
                sanitise_for_terminal(type(exc).__name__, max_len=64),
                sanitise_for_terminal(str(exc)),
            )
            return False
        # Validate both snapshots: a safe pathname stat cannot overrule
        # metadata that becomes unsafe before inspecting the held object.
        for location, snapshot in (("path", st), ("descriptor", held)):
            if not _safe_evidence_file_metadata(snapshot):
                logger.warning(
                    "SANDBOX EVIDENCE TAMPER SUSPECTED: unsafe evidence "
                    "metadata for %s (%s: mode=%o uid=%s nlink=%s)",
                    sanitise_for_terminal(str(self.path)), location, snapshot.st_mode,
                    snapshot.st_uid, snapshot.st_nlink,
                )
                return False
        minimum_size = max(written_end, self._minimum_size)
        if size < minimum_size:
            logger.warning(
                "SANDBOX EVIDENCE TAMPER SUSPECTED: evidence file %s "
                "was truncated below known append progress (%s bytes < %s). "
                "Treat this run's evidence as compromised.",
                sanitise_for_terminal(str(self.path)), size, minimum_size,
            )
            return False
        return True

    def close(self, *, verify: bool = True) -> bool:
        """Finalise: optionally verify identity and size, then close the fd.

        Returns True only when verification is skipped or clean and the
        descriptor closes successfully. Close I/O errors warn and return
        False. Repeated closes return the cached result. Other errors
        propagate after cleanup and leave a failed result.
        """
        with self._io_lock:
            if self._closed:
                return self._close_result
            self._closed = True
            verification_result = False
            try:
                verification_result = self.verify() if verify else True
            finally:
                # Verify while the fd is owned, but publish success only
                # after close completes. Never retry a released fd number.
                self._fd_released = True
                try:
                    os.close(self.fd)
                except OSError as exc:
                    # Raw tracebacks can put path/error controls back into
                    # logs after message escaping. Retain bounded context.
                    logger.warning(
                        "evidence close failed for %s: %s: %s",
                        sanitise_for_terminal(str(self.path)),
                        sanitise_for_terminal(type(exc).__name__, max_len=64),
                        sanitise_for_terminal(str(exc)),
                    )
                else:
                    self._close_result = verification_result
            return self._close_result


# ---------------------------------------------------------------------------
# Anonymous config delivery (F31)
# ---------------------------------------------------------------------------

def anonymous_fd(data: bytes, *, name: str = "raptor-audit-cfg") -> int:
    """Return a read/write fd holding ``data``, with no filesystem name.

    Linux: ``memfd_create`` — the object never touches a filesystem.
    When unavailable (including older kernels) or elsewhere (macOS),
    use an unlinked temp file — opened, unlinked, then
    written; the fd stays valid but no path exists to discover.

    The fd is close-on-exec (Python fds are non-inheritable by
    default); callers clear that only in the tracer child's post-fork
    branch, never for the target's exec. Offset is rewound to 0 so a
    same-description reader (the ``/dev/fd/N`` dup on macOS) reads
    from the start.
    """
    fd = None
    path = None
    try:
        if sys.platform.startswith("linux") and hasattr(os, "memfd_create"):
            try:
                fd = os.memfd_create(name)
            except OSError as exc:
                if exc.errno != errno.ENOSYS:
                    raise
                # Python may expose the API on an older running kernel.
                # The unlinked-file branch has the same no-name contract.
        if fd is None:
            fd, path = tempfile.mkstemp(prefix=name + "-")
            os.unlink(path)
            path = None

        remaining = memoryview(data)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError(errno.EIO, "anonymous-fd write made no progress")
            remaining = remaining[written:]
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        if path is not None:
            with contextlib.suppress(OSError):
                os.unlink(path)
        raise


def fd_path(fd: int, *, platform: str | None = None) -> str:
    """Spell the self-referential path for an inherited fd.

    Linux uses ``/proc/self/fd/N`` (opening it yields a fresh file
    description at offset 0 for a memfd); macOS has no /proc and uses
    ``/dev/fd/N`` (a dup of the descriptor — offset shared, which is
    why :func:`anonymous_fd` rewinds). ``self`` is resolved by the
    PROCESS THAT OPENS THE PATH — the tracer — so the argv value is
    meaningless to any other process reading it.
    """
    plat = platform if platform is not None else sys.platform
    if plat.startswith("linux"):
        return f"/proc/self/fd/{int(fd)}"
    return f"/dev/fd/{int(fd)}"


def parse_fd_path(path: str) -> int | None:
    """Inverse of :func:`fd_path` — extract N from ``/proc/self/fd/N``
    or ``/dev/fd/N``; None for any other path shape. Used by the
    tracer to close its inherited config fd right after parsing."""
    for prefix in ("/proc/self/fd/", "/dev/fd/"):
        if path.startswith(prefix):
            tail = path[len(prefix):]
            # fd_path emits ASCII decimal digits only. isdigit() also
            # accepts characters such as superscripts that int() rejects.
            if tail.isascii() and tail.isdecimal():
                try:
                    return int(tail)
                except ValueError:
                    # Python bounds decimal conversion of oversized strings.
                    return None
            return None
    return None
