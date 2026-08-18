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
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Scan-root context: when set (by the pipeline around its parse loop),
# ``read_bounded(..., follow_symlinks=False)`` accepts a symlinked
# manifest whose fully-resolved target still lies INSIDE the scan
# root — the legitimate monorepo pattern (pnpm / nix / Bazel layouts
# symlink shared manifests within the tree) — while continuing to
# refuse links that escape it (``composer.lock -> /etc/shadow``).
# Contextvar (not a module global) so parallel scans in one process
# can't leak each other's roots.
_SCAN_ROOT: contextvars.ContextVar[Optional[Path]] = contextvars.ContextVar(
    "sca_parser_scan_root", default=None,
)


@contextlib.contextmanager
def scan_root_context(root: Path) -> Iterator[None]:
    """Declare the scan root for symlink containment checks."""
    token = _SCAN_ROOT.set(Path(root).resolve())
    try:
        yield
    finally:
        _SCAN_ROOT.reset(token)

# 50 MB. See module docstring for the bound rationale.
_MAX_PARSER_BYTES = 50 * 1024 * 1024


def read_bounded(
    path: Path, *, max_bytes: int = _MAX_PARSER_BYTES,
    follow_symlinks: bool = True,
) -> Optional[str]:
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
    try:
        st = (path.lstat() if not follow_symlinks else path.stat())
    except OSError as e:
        logger.warning("sca.parsers: cannot stat %s: %s", path, e)
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
                    "sca.parsers: cannot resolve symlink %s: %s",
                    path, e,
                )
                return None
            if resolved.is_relative_to(root):
                return read_bounded(
                    resolved, max_bytes=max_bytes,
                    follow_symlinks=False,
                )
            logger.warning(
                "sca.parsers: refusing symlinked manifest %s — "
                "resolves outside the scan root (%s); treating as "
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
        logger.warning("sca.parsers: cannot read %s: %s", path, e)
        return None
    if len(raw) > max_bytes:
        logger.warning(
            "sca.parsers: %s grew past max during read (>%d); "
            "treating as unparseable", path, max_bytes,
        )
        return None
    return raw.decode("utf-8", errors="replace")
