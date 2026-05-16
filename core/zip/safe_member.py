"""Zip member safety predicate.

Zip lacks a stdlib equivalent of :func:`tarfile.data_filter` (PEP 706
covers tar only), so this module hand-rolls the same hardening rules
against :class:`zipfile.ZipInfo`. Mirrors :mod:`core.tar.safe_member`
in shape, return type and tunables, so callers that walk both
formats can share a single inspection loop.

The hardening rules:

  * **Path traversal** — member name resolved against the extraction
    destination must not escape it. Zip slip
    (``../../../etc/passwd``) is the canonical example.
  * **Absolute paths** — leading ``/`` rejected; a zip extracting to
    ``/usr/local`` shouldn't write to ``/etc``.
  * **Backslash separator** — Windows-shaped paths inside zips
    legitimately use ``\\``; we reject so the on-disk resolver
    can't be fooled by ``..\\..\\etc\\passwd`` on a POSIX host.
  * **Symlinks** — zip stores Unix mode in
    ``external_attr >> 16``. We refuse any member whose mode
    matches ``S_IFLNK``. Symlink-aware unpacking is a footgun;
    nothing in raptor needs it.
  * **Special files** — block / char devices, FIFOs, sockets.
    None should ever appear in a "data" zip.
  * **Oversized members** — per-member uncompressed size cap.
    Defends against "package-state file the size of the whole
    archive".
  * **Compression-bomb ratio** — zip's specific risk: high
    compression ratio means a small archive can yield a huge
    extraction. We reject any member where uncompressed /
    compressed exceeds the configured threshold.

The compression-ratio check is the substantive difference from
:mod:`core.tar.safe_member`. Tar's bombs are usually structural
(deep nesting, symlink cycles); zip's are ratio-driven.

Usage:

    for info in zf.infolist():
        if not is_safe_member(info):
            continue
        # extract member safely
"""

from __future__ import annotations

import logging
import stat
import unicodedata
import zipfile
from enum import Enum

logger = logging.getLogger(__name__)


# Sane upper bound — matches core.tar default. 64 MB is generous for
# real data files; anything bigger is either misuse of zip (use a
# different format) or a malicious bomb.
DEFAULT_MAX_MEMBER_BYTES = 64 * 1024 * 1024

# Compression-ratio threshold. A 1 GiB-of-zeros file legitimately
# compresses ~1000:1, but 1 GiB of zeros is not a member operators
# ship inside a data zip. Real data caps around 20-50:1 for
# heavily-redundant text. Above 200 is the zone where the bomb
# explanation is more plausible than the data explanation.
DEFAULT_MAX_RATIO = 200


class UnsafeMemberReason(str, Enum):
    """Reason a zip member was rejected. Surfaced via
    :func:`safe_member_reason` so callers can log specific causes
    or aggregate by class. Values overlap with
    :class:`core.tar.safe_member.UnsafeMemberReason` where the
    concept maps cleanly; ``COMPRESSION_BOMB`` is zip-specific."""
    SAFE = "safe"
    PATH_TRAVERSAL = "path_traversal"
    ABSOLUTE_PATH = "absolute_path"
    BACKSLASH_PATH = "backslash_path"
    SPECIAL_FILE = "special_file"           # block / char dev, fifo, socket
    SYMLINK_UNSAFE = "symlink_unsafe"
    OVERSIZED = "oversized"
    COMPRESSION_BOMB = "compression_bomb"
    UNRECOGNISED_TYPE = "unrecognised_type"


def is_safe_member(
    info: zipfile.ZipInfo,
    *,
    max_size: int = DEFAULT_MAX_MEMBER_BYTES,
    max_ratio: int = DEFAULT_MAX_RATIO,
    allow_absolute_paths: bool = False,
) -> bool:
    """True if extracting ``info`` is safe under the hardening rules.
    Boolean wrapper over :func:`safe_member_reason`."""
    return safe_member_reason(
        info,
        max_size=max_size, max_ratio=max_ratio,
        allow_absolute_paths=allow_absolute_paths,
    ) == UnsafeMemberReason.SAFE


def safe_member_reason(
    info: zipfile.ZipInfo,
    *,
    max_size: int = DEFAULT_MAX_MEMBER_BYTES,
    max_ratio: int = DEFAULT_MAX_RATIO,
    allow_absolute_paths: bool = False,
) -> UnsafeMemberReason:
    """Return the specific reason ``info`` is unsafe, or
    :data:`UnsafeMemberReason.SAFE`.

    ``allow_absolute_paths`` is for read-into-memory consumers
    (e.g. wheel inspection matching against a wanted-paths set
    without touching disk). Default ``False`` — conservative for
    consumers that DO extract to a destination directory.

    ``max_ratio`` is zip-specific compression bomb defense. Set
    to a very large number (e.g. ``10_000_000``) to effectively
    disable — useful for tightly-controlled archives where the
    consumer trusts the producer (raptor's own export, for
    example), but the default catches the operator-facing case.
    """
    # Size check first — cheap, and a 1 GiB malicious entry should
    # be rejected before doing anything else with it.
    if info.file_size > max_size:
        return UnsafeMemberReason.OVERSIZED

    # Compression-bomb ratio check. ``compress_size`` of zero means
    # the entry is empty (or a directory marker) — skip the ratio
    # math to avoid division-by-zero on legitimate empty files.
    if info.compress_size > 0 and info.file_size > 0:
        ratio = info.file_size / info.compress_size
        if ratio > max_ratio:
            return UnsafeMemberReason.COMPRESSION_BOMB

    name = info.filename or ""

    # Empty name shouldn't really happen but defensive.
    if not name:
        return UnsafeMemberReason.UNRECOGNISED_TYPE

    # Directories are valid members but extract_files_from_zip
    # skips them before this is even called; we accept them so
    # consumers using safe_member_reason for full archive walks
    # don't have to special-case the directory shape.

    # Absolute-path check.
    if not allow_absolute_paths:
        if name.startswith("/"):
            return UnsafeMemberReason.ABSOLUTE_PATH

    # Backslash check. Zip spec uses forward slash; any backslash
    # is either a malformed producer or an intentional Windows
    # path attack on POSIX hosts. Reject explicitly so the on-
    # disk resolver doesn't have to handle the case.
    if "\\" in name:
        return UnsafeMemberReason.BACKSLASH_PATH

    # Path-traversal check (zip slip). Reject any segment that
    # equals ``..``. We split on ``/`` because zip spec requires
    # forward slash even on Windows producers — the backslash
    # check above already filtered legacy Windows producers.
    #
    # NFKC normalization: HFS+ (macOS) and some case-insensitive
    # filesystems map fullwidth/decomposed Unicode forms back to
    # their ASCII equivalents during write. ``safe/．．/x``
    # (FULLWIDTH FULL STOP) extracts as ``safe/../x`` on those
    # filesystems → real path escape. Apply NFKC for the safety
    # check only — the original name is left intact for callers
    # that want to surface the raw value.
    normalised = unicodedata.normalize("NFKC", name)
    for to_check in {name, normalised}:
        parts = [p for p in to_check.split("/") if p]
        if ".." in parts:
            return UnsafeMemberReason.PATH_TRAVERSAL
        # Re-run absolute-path check on the normalised form too.
        # Some Unicode whitespace + dot combos could resolve to a
        # leading "/" after NFKC.
        if not allow_absolute_paths and to_check.startswith("/"):
            return UnsafeMemberReason.ABSOLUTE_PATH

    # Symlink / special-file check via Unix mode in external_attr.
    # The high 16 bits of external_attr carry the POSIX mode for
    # zips produced by unix tooling. Windows-produced zips have
    # 0 here (DOS attributes in low 16 bits) — that's fine, we
    # only act on the mode when it's set to a special-file type.
    mode = (info.external_attr >> 16) & 0xFFFF
    if mode:
        if stat.S_ISLNK(mode):
            return UnsafeMemberReason.SYMLINK_UNSAFE
        if (stat.S_ISBLK(mode) or stat.S_ISCHR(mode)
                or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
            return UnsafeMemberReason.SPECIAL_FILE

    return UnsafeMemberReason.SAFE


__all__ = [
    "DEFAULT_MAX_MEMBER_BYTES",
    "DEFAULT_MAX_RATIO",
    "UnsafeMemberReason",
    "is_safe_member",
    "safe_member_reason",
]
