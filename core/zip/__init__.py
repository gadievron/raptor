"""Zip primitives for attacker-influenced archives.

Mirrors :mod:`core.tar` in shape. Several raptor consumers walk
zip archives we didn't author:

  * ``packages/sca/llm/version_diff_review`` — PyPI / Cargo /
    npm source archives in zip form. Reads from in-memory blob,
    filters by extension, strips top-level dir.
  * ``packages/sca/python_modules`` — PyPI wheel inspection
    (targeted ``top_level.txt`` read; stays direct).
  * ``packages/codeql/database_manager`` — CodeQL database
    archives extracted to a destination directory.

All share two concerns: deciding whether a member is safe to
extract, and walking the archive to pull out the members the
caller wants. This module centralises both:

  * :func:`safe_member_reason` — same hardening rules as
    :mod:`core.tar.safe_member` plus a compression-ratio bomb
    check that's zip-specific. Returns
    :class:`UnsafeMemberReason` for diagnostic logging.
  * :func:`extract_files_from_zip` — generic zip walker that
    applies the safety filter, asks a consumer-supplied
    selector for the dict key (or ``None`` to skip), and
    returns ``{key: bytes}``.

Differences from :mod:`core.tar`:

  * No streaming-from-chunk-iterator mode. Zip's central
    directory lives at the end of the archive, so parsing
    requires seek. Consumers with a streaming source must
    buffer first.
  * Adds ``max_ratio`` compression-bomb defense. Zip's
    strength is high compression ratios; the tar equivalent
    is structural (deep nesting, symlink cycles) rather than
    ratio-driven.

Limitations:

  * Doesn't cover ZIP64 specifics beyond what stdlib
    ``zipfile`` handles. ZIP64 size fields are read correctly
    by stdlib; the size cap applies in bytes regardless.
  * Encrypted entries are surfaced as read failures (logged
    at debug). We don't try to crack or guess passwords.
"""

from .eocd import DEFAULT_MAX_ENTRIES, peek_total_entries
from .extract import ZipEntryCountExceeded, extract_files_from_zip
from .safe_member import (
    DEFAULT_MAX_MEMBER_BYTES,
    DEFAULT_MAX_RATIO,
    UnsafeMemberReason,
    is_safe_member,
    safe_member_reason,
)

__all__ = [
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_MAX_MEMBER_BYTES",
    "DEFAULT_MAX_RATIO",
    "UnsafeMemberReason",
    "ZipEntryCountExceeded",
    "extract_files_from_zip",
    "is_safe_member",
    "peek_total_entries",
    "safe_member_reason",
]
