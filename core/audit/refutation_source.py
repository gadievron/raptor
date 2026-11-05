"""Bounded source identity for negative verification receipts."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path

from core.paths import confine
from core.source import open_regular_beneath


# Whole-file hashing keeps edits outside the excerpt from preserving a
# receipt. A larger cap admits generated sources at higher per-probe
# read cost; oversized files remain unverified, never prefix-hashed.
MAX_SOURCE_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class SourceIdentity:
    sha256: str
    version: tuple[int, ...]


def _version(st) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def capture_source_identity(root, file, *, excerpt=None, line_start=0) -> SourceIdentity | None:
    """Hash one confined regular file, refusing partial or unstable reads.

    The inode/change stamp also detects rewrite-and-restore between
    checks. This is a before/after guard, not an immutable build snapshot
    or a digest of included headers and other dependencies.
    """
    path = confine(root, file)
    if path is None:
        return None
    try:
        base = Path(root).resolve()
        stream = open_regular_beneath(base, path.relative_to(base), "rb")
        if stream is None:
            return None
        with stream:
            before = os.fstat(stream.fileno())
            if before.st_size > MAX_SOURCE_BYTES:
                return None
            data = stream.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(stream.fileno())
        if len(data) > MAX_SOURCE_BYTES or len(data) != before.st_size or _version(before) != _version(after):
            return None
    except (OSError, ValueError, RuntimeError):
        return None
    if excerpt:
        text = data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
        snippet = excerpt.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
        start = max(0, (line_start or 1) - 1)
        window = "\n".join(text.split("\n")[start:start + len(snippet.split("\n"))])  # line-model: text and snippet normalize CRLF and bare CR above
        if snippet != text.rstrip("\n") and snippet != window:
            return None  # a cached excerpt is not the source now on disk
    return SourceIdentity(hashlib.sha256(data).hexdigest(), _version(after))
