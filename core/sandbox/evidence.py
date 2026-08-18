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
import json
import logging
import os
import stat as _stat
import sys
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Subdirectory of the run dir that holds enforcement evidence. The
# leading dot keeps it out of operator-facing listings; the name is
# load-bearing for the mount-ns shadowing (mount_ns.py) and the macOS
# seatbelt deny rule (seatbelt.build_profile) — all three must agree.
AUDIT_SUBDIR = ".audit"


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
    location so error messages point at the canonical path.
    """
    new = evidence_write_path(run_dir, filename)
    if new.exists():
        return new
    old = legacy_read_path(run_dir, filename)
    if old.exists():
        return old
    return new


def ensure_audit_dir(run_dir) -> Path:
    """Create ``<run_dir>/.audit`` mode 0700 if needed; return it.

    Refuses a symlink at the ``.audit`` path — a pre-planted symlink
    would redirect evidence into an attacker-chosen directory.
    """
    d = audit_dir_path(run_dir)
    try:
        os.mkdir(d, 0o700)
    except FileExistsError:
        st = os.lstat(d)
        if not _stat.S_ISDIR(st.st_mode):
            raise OSError(
                f"evidence dir {d} exists and is not a directory "
                f"(symlink or file planted?) — refusing to use it"
            ) from None
    return d


class EvidenceFile:
    """A parent-held, append-only evidence JSONL.

    Created with ``O_EXCL`` (or validated append when a previous
    sandbox call in the same run already created it), fd held for the
    file's lifetime, inode recorded at open and verified at
    finalisation. All appends go through the held fd — writers that
    inherit the fd (the ptrace tracer) share the same open file
    description, so a rename/unlink of the path cannot redirect their
    appends.
    """

    def __init__(self, fd: int, path: Path, st: os.stat_result):
        self.fd = fd
        self.path = path
        self._created_dev = st.st_dev
        self._created_ino = st.st_ino
        self._closed = False

    @classmethod
    def open(cls, run_dir, filename: str) -> EvidenceFile:
        """Create (or validate-and-append-to) the evidence file.

        First choice is ``O_CREAT|O_EXCL`` — defeats pre-created files
        and symlinks planted before sandbox start. When the file
        already exists (a prior sandbox call in the same run created
        it), it is re-opened without ``O_CREAT`` and accepted only if
        it is a regular, non-hard-linked file owned by us with no
        group/other write bits.
        """
        ensure_audit_dir(run_dir)
        path = evidence_write_path(run_dir, filename)
        flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(str(path), flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            fd = os.open(str(path), flags)
            st = os.fstat(fd)
            ok = (
                _stat.S_ISREG(st.st_mode)
                and st.st_uid == os.getuid()
                and st.st_nlink == 1
                and not (st.st_mode & 0o022)
            )
            if not ok:
                os.close(fd)
                raise OSError(
                    f"existing evidence file {path} failed validation "
                    f"(mode={oct(st.st_mode)}, uid={st.st_uid}, "
                    f"nlink={st.st_nlink}) — refusing to append"
                ) from None
            return cls(fd, path, st)
        return cls(fd, path, os.fstat(fd))

    def write_line(self, line: str) -> bool:
        """Append one JSONL line through the held fd. Returns True on
        success. O_APPEND keeps sub-PIPE_BUF writes atomic against
        concurrent appenders sharing the same file."""
        if self._closed:
            return False
        try:
            os.write(self.fd, line.encode("utf-8"))
            return True
        except OSError:
            logger.warning("evidence append failed for %s", self.path,
                           exc_info=True)
            return False

    def write_record(self, record: dict) -> bool:
        """JSON-encode ``record`` and append it as one line."""
        try:
            line = json.dumps(record, ensure_ascii=True, default=str) + "\n"
        except (TypeError, ValueError):
            logger.warning("evidence record not serialisable", exc_info=True)
            return False
        return self.write_line(line)

    def verify(self) -> bool:
        """Check the path still names the inode we created.

        Returns True when it does. On mismatch (or a missing file) a
        LOUD warning fires: someone with write access to the evidence
        directory swapped or removed the file — the on-disk JSONL at
        this path can no longer be trusted, even though every append
        made through the held fd went to the original inode.
        """
        try:
            st = os.stat(self.path, follow_symlinks=False)
        except OSError:
            logger.warning(
                "SANDBOX EVIDENCE TAMPER SUSPECTED: evidence file %s "
                "vanished during the run (created dev=%s ino=%s). "
                "Records appended via the held fd are intact in the "
                "original inode but the on-disk path was removed.",
                self.path, self._created_dev, self._created_ino,
            )
            return False
        if (st.st_dev, st.st_ino) != (self._created_dev, self._created_ino):
            logger.warning(
                "SANDBOX EVIDENCE TAMPER SUSPECTED: evidence file %s "
                "was swapped during the run (created dev=%s ino=%s, "
                "now dev=%s ino=%s). Do not trust the file at this "
                "path; treat this run's evidence as compromised.",
                self.path, self._created_dev, self._created_ino,
                st.st_dev, st.st_ino,
            )
            return False
        return True

    def close(self, *, verify: bool = True) -> bool:
        """Finalise: optionally verify the inode, then close the fd.

        Returns the verification result (True when skipped or clean).
        Idempotent — a second close is a no-op returning True.
        """
        if self._closed:
            return True
        ok = self.verify() if verify else True
        self._closed = True
        with contextlib.suppress(OSError):
            os.close(self.fd)
        return ok


# ---------------------------------------------------------------------------
# Anonymous config delivery (F31)
# ---------------------------------------------------------------------------

def anonymous_fd(data: bytes, *, name: str = "raptor-audit-cfg") -> int:
    """Return a read/write fd holding ``data``, with no filesystem name.

    Linux: ``memfd_create`` — the object never touches a filesystem.
    Elsewhere (macOS): an unlinked temp file — opened, unlinked, then
    written; the fd stays valid but no path exists to discover.

    The fd is close-on-exec (Python fds are non-inheritable by
    default); callers clear that only in the tracer child's post-fork
    branch, never for the target's exec. Offset is rewound to 0 so a
    same-description reader (the ``/dev/fd/N`` dup on macOS) reads
    from the start.
    """
    if sys.platform.startswith("linux") and hasattr(os, "memfd_create"):
        fd = os.memfd_create(name)
    else:
        fd, path = tempfile.mkstemp(prefix=name + "-")
        try:
            os.unlink(path)
        except OSError:
            # The unlink is what removes the discoverable path; if it
            # fails we must not fall through to using a named file.
            with contextlib.suppress(OSError):
                os.close(fd)
            raise
    try:
        written = 0
        while written < len(data):
            n = os.write(fd, data[written:])
            if n <= 0:
                raise OSError(
                    "anonymous-fd write returned 0 bytes — "
                    "filesystem full or read-only"
                )
            written += n
        os.lseek(fd, 0, os.SEEK_SET)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise
    return fd


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
            if tail.isdigit():
                return int(tail)
            return None
    return None
