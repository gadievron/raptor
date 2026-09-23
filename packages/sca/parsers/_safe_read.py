"""Bounded file-read helper for SCA parsers.

Every parser in this package reads attacker-controlled target-repo
files. Without an in-process size bound, a hostile manifest can
exhaust the parser's memory before the sandbox-level limit kicks
in — which is the right fail-closed posture for the sandbox, but
leaves the operator-facing tool with a "OOMKilled at line 137"
error message instead of a clean ``treating as unparseable``
verdict.

This helper caps reads at ``_MAX_PARSER_BYTES`` (50 MB by default).
That's:

  * Above the largest legitimate ``package-lock.json`` /
    ``yarn.lock`` / ``Cargo.lock`` seen in the wild (the biggest
    monorepos run ~30-40 MB).
  * Below the magnitude of zip-bomb / DoS payloads, which tend to
    be 100s of MB to GB.

Mirrors ``core.inventory.builder.MAX_FILE_BYTES`` (8 MiB for
source code) — same defensive shape, looser cap because SCA
manifests legitimately run larger than source files.

Other parsers in this package read target files via
``path.read_text(encoding="utf-8")`` without a bound. They should
migrate to this helper; until they do, the OS-level fail (sandbox
memory limit) is the backstop. New parsers added to the package
should use this from the start.
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
import os
import stat as _stat
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)

# Scan-root context: when set (by the pipeline around its parse loop),
# ``read_bounded(..., follow_symlinks=False)`` accepts a symlinked
# manifest whose fully-resolved target still lies INSIDE the scan
# root — the legitimate monorepo pattern (pnpm / nix / Bazel layouts
# symlink shared manifests within the tree) — while continuing to
# refuse links that escape it (``composer.lock -> /etc/shadow``).
# Contextvar (not a module global) so parallel scans in one process
# can't leak each other's roots.
_SCAN_ROOT: contextvars.ContextVar[Path | None] = contextvars.ContextVar(
    "sca_parser_scan_root", default=None,
)


@contextlib.contextmanager
def sidecar_lock(path: Path) -> Iterator[None]:
    """Exclusive advisory flock on ``<path>.lock`` — serialises a
    read-modify-write cycle on ``path`` across processes (an atomic
    replace protects against torn FILES, not lost UPDATES). The lock
    rides a SIDECAR because ``os.replace`` swaps the data file's
    inode out from under any lock taken on it, and the lock file is
    deliberately never unlinked (unlink-after-unlock races split
    lockers across two inodes — same doctrine as the core sidecar
    locks). Hosts without ``fcntl`` fall back to unlocked."""
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import fcntl
    except ImportError:  # pragma: no cover — non-POSIX fallback
        yield
        return
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


@contextlib.contextmanager
def scan_root_context(root: Path) -> Iterator[None]:
    """Declare the scan root for symlink containment checks."""
    token = _SCAN_ROOT.set(Path(root).resolve())
    try:
        yield
    finally:
        _SCAN_ROOT.reset(token)


def active_scan_root() -> Path | None:
    """The scan root declared by :func:`scan_root_context`, or ``None``.

    Parsers that confine cross-file reads (``-r`` includes, parent
    POMs) use this as their containment bound when the caller didn't
    pass one explicitly — the pipeline wraps its parse loop in
    ``scan_root_context(target)``, so registry-dispatched parsers get
    the real target root instead of guessing from the manifest path.
    """
    return _SCAN_ROOT.get()

# 50 MB. See module docstring for the bound rationale.
_MAX_PARSER_BYTES = 50 * 1024 * 1024


def read_bounded(
    path: Path, *, max_bytes: int = _MAX_PARSER_BYTES,
    follow_symlinks: bool = True,
) -> str | None:
    """Read ``path`` as UTF-8 text, capped at ``max_bytes``.

    Returns ``None`` and logs at warning level when:

      * the file can't be stat'd (vanished, permission denied)
      * the file exceeds ``max_bytes`` per its stat
      * the file grew past ``max_bytes`` between stat and read
        (racing writer; OS-level TOCTOU defence)
      * any OSError fires during the read

    Mirrors the ``core.inventory.builder._read_source_text``
    pattern: stat first to reject before opening, then read with
    ``+1`` and double-check so a file that grew between stat and
    read still surfaces as unparseable rather than silently
    truncating.

    Decodes with ``errors="replace"`` so adversarial byte sequences
    don't crash the parser — the caller's regex / JSON parse
    handles the resulting U+FFFD replacement chars as gracefully
    as it handles legitimate non-UTF-8 manifests.

    When ``follow_symlinks=False`` is set, both the stat and the
    open refuse to traverse a symlink at the final path component
    (the open uses ``O_NOFOLLOW``; the stat uses ``lstat``). A
    hostile target with ``Directory.Packages.props -> /etc/shadow``
    is rejected here instead of leaking privileged file contents
    into the parser's error logs. Defaults to ``True`` for
    backward compatibility; new SCA parser sites that read attacker-
    controlled manifest paths should pass ``follow_symlinks=False``.
    """
    # Every refusal below uses the canonical ``refusing to read
    # <path> (<reason>)`` shape the parse-failure collector matches —
    # a skipped manifest must reach the run report's structured
    # parse_failures, not just the log stream (this module's whole
    # reason to warn instead of silently returning None).
    try:
        st = (path.lstat() if not follow_symlinks else path.stat())
    except OSError as e:
        logger.warning(
            "sca.parsers: refusing to read %s (cannot stat: %s)", path, e,
        )
        return None
    if not follow_symlinks and _stat.S_ISLNK(st.st_mode):
        # Symlinked manifest. With a declared scan root, resolve and
        # allow when the target stays inside it (monorepo shared-
        # manifest layouts); otherwise fall through to the refusal
        # below. The recursive call re-runs the full bound/regular-
        # file checks on the resolved target, and its O_NOFOLLOW
        # open closes the resolve->open TOCTOU window (a re-linked
        # final component fails with ELOOP rather than following).
        root = _SCAN_ROOT.get()
        if root is not None:
            try:
                resolved = path.resolve(strict=True)
            except OSError as e:
                logger.warning(
                    "sca.parsers: refusing to read %s "
                    "(cannot resolve symlink: %s)", path, e,
                )
                return None
            if resolved.is_relative_to(root):
                return read_bounded(
                    resolved, max_bytes=max_bytes,
                    follow_symlinks=False,
                )
            logger.warning(
                "sca.parsers: refusing to read %s (symlinked manifest "
                "resolves outside the scan root: %s); treating as "
                "unparseable", path, resolved,
            )
            return None
    # Reject non-regular files up-front (symlinks, sockets, FIFOs,
    # devices). With ``follow_symlinks=False`` ``lstat`` reports
    # the symlink itself, so the S_ISLNK check is what blocks the
    # symlink read (unless the scan-root containment branch above
    # accepted it). With ``follow_symlinks=True`` ``stat`` follows
    # transparently and this check rejects only non-regular final
    # targets (FIFO, socket, etc.).
    if not _stat.S_ISREG(st.st_mode):
        logger.warning(
            "sca.parsers: refusing to read %s (not a regular file: "
            "mode=0o%o); treating as unparseable", path, st.st_mode,
        )
        return None
    size = st.st_size
    if size > max_bytes:
        logger.warning(
            "sca.parsers: refusing to read %s (size=%d > max=%d) "
            "— hostile or unusually large manifest; treating as "
            "unparseable", path, size, max_bytes,
        )
        return None
    try:
        if not follow_symlinks:
            # ``O_NOFOLLOW`` raises ELOOP if the final component
            # is a symlink — defends against the TOCTOU window
            # between the ``lstat`` above and this open.
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb", closefd=True) as fh:
                raw = fh.read(max_bytes + 1)
        else:
            with path.open("rb") as fh:
                raw = fh.read(max_bytes + 1)
    except OSError as e:
        logger.warning(
            "sca.parsers: refusing to read %s (cannot read: %s)", path, e,
        )
        return None
    if len(raw) > max_bytes:
        logger.warning(
            "sca.parsers: refusing to read %s (grew past max=%d "
            "during read); treating as unparseable", path, max_bytes,
        )
        return None
    return raw.decode("utf-8", errors="replace")


def read_head_bytes(path: Path, *, max_bytes: int) -> bytes | None:
    """Read at most ``max_bytes`` raw bytes from ``path``, refusing
    symlinks and non-regular files.

    The binary-sniffing detectors (magic-byte classification,
    obfuscation entropy, URL extraction from source bytes) only ever
    need a bounded prefix, so unlike :func:`read_bounded` an
    oversized file is TRUNCATED rather than refused.  What this
    helper exists to block is the same class the text reader blocks:

      * a symlinked path leaking host-file bytes into operator-facing
        finding details,
      * a FIFO / device node hanging or flooding the scan
        (``open()`` on a FIFO blocks until a writer appears; reads
        from ``/dev/zero`` never end).

    Returns ``None`` (after a debug log — these are per-file sniffs
    on arbitrary tree walks, warning-level would flood) when the path
    is a symlink, not a regular file, or unreadable.
    """
    try:
        st = path.lstat()
    except OSError as e:
        logger.debug("sca.parsers: cannot lstat %s: %s", path, e)
        return None
    if not _stat.S_ISREG(st.st_mode):
        logger.debug(
            "sca.parsers: refusing byte read of %s (not a regular "
            "file: mode=0o%o)", path, st.st_mode,
        )
        return None
    try:
        # ``O_NOFOLLOW`` closes the lstat→open TOCTOU window for the
        # symlink case (re-linked final component fails with ELOOP);
        # ``O_NONBLOCK`` closes it for the FIFO case (a FIFO swapped
        # in after the lstat opens immediately instead of blocking
        # until a writer appears — the fstat below then rejects it).
        fd = os.open(
            str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        try:
            if not _stat.S_ISREG(os.fstat(fd).st_mode):
                logger.debug(
                    "sca.parsers: refusing byte read of %s (became "
                    "non-regular between lstat and open)", path,
                )
                return None
            with os.fdopen(fd, "rb", closefd=True) as fh:
                fd = -1
                return fh.read(max_bytes)
        finally:
            if fd >= 0:
                os.close(fd)
    except OSError as e:
        logger.debug("sca.parsers: cannot read %s: %s", path, e)
        return None
