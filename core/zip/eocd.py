"""End-of-Central-Directory (EOCD) pre-flight for zip entry-count cap.

``zipfile.ZipFile.__init__`` reads the entire central directory into
memory before any consumer code runs — a zip-bomb-shaped archive with
millions of entries causes a multi-GB RSS spike there regardless of
any downstream cap. Reading the EOCD record up-front lets callers
reject the archive before paying that cost.

This module ports the EOCD primitives that originated in
``core/project/export.py`` (PR #514, fix(core): zip-bomb cap parity,
@gevron) into the generic substrate so every zip consumer can opt in
to the same defense.

API:
  * :func:`peek_total_entries` — read EOCD from a path (Path / str),
    return total entry count or ``None`` if EOCD parsing failed.
  * :data:`DEFAULT_MAX_ENTRIES` — the conventional cap (10 000).
    Legitimate raptor archives have << 1000 entries; CodeQL DBs and
    third-party wheels are well under 10k.

ZIP64 sentinels (``entries_total == 0xFFFF``) follow the locator
back to the ZIP64 EOCD record at the absolute offset stored in the
locator. Malformed / unparseable archives return ``None`` so the
caller can fall through to the normal ZipFile() path (which will
raise ``BadZipFile`` for genuinely broken inputs).
"""

from __future__ import annotations

import logging
import os
import struct
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger(__name__)


# Cap on a zip archive's entry count. 10 000 is generous for every
# real consumer — raptor's own project exports have a few hundred
# entries, CodeQL DB archives a few thousand, PyPI sdists tens to
# hundreds. Above 10k the bomb hypothesis dominates the data one.
DEFAULT_MAX_ENTRIES = 10_000

# EOCD record format (PKZIP appnote 4.3.16):
#   signature (4) | disk# (2) | cd-disk (2) | entries-on-disk (2) |
#   total-entries (2) | cd-size (4) | cd-offset (4) | comment-len (2) | comment
# ZIP64 EOCD locator (PKZIP appnote 4.3.15) signature:
#   b"\x50\x4b\x06\x07" — points back to the ZIP64 EOCD record
#   (signature b"\x50\x4b\x06\x06") which carries an 8-byte
#   total-entries field at offset +32.
_EOCD_SIG = b"\x50\x4b\x05\x06"
_ZIP64_EOCD_SIG = b"\x50\x4b\x06\x06"
_ZIP64_EOCD_LOCATOR_SIG = b"\x50\x4b\x06\x07"

# Comment ≤ 65535 (uint16) + 22-byte fixed EOCD header.
_EOCD_SEARCH_BYTES = 65557


def peek_total_entries(
    source: Union[Path, str, bytes],
) -> Optional[int]:
    """Read the EOCD pre-flight from ``source`` and return the zip's
    declared total entry count, or ``None`` on unparseable EOCD.

    ``source`` accepts:
      * ``Path`` / ``str`` — a filesystem path; we ``stat`` for size
        and seek-read the trailing bytes.
      * ``bytes`` — an in-memory zip; we read trailing bytes from
        the buffer directly.

    A ``None`` return means "couldn't parse the EOCD record" — the
    caller should fall through to ``zipfile.ZipFile()`` which will
    raise ``BadZipFile`` for genuinely malformed archives, or
    succeed for unusual-but-valid archives that lack the parseable
    EOCD shape this helper recognises.

    For deliberately-malicious bomb-shaped archives that nonetheless
    parse cleanly, the returned count will exceed the cap and the
    caller's gate fires.
    """
    if isinstance(source, (bytes, bytearray)):
        return _peek_from_bytes(bytes(source))
    return _peek_from_path(Path(source))


def _peek_from_path(zip_path: Path) -> Optional[int]:
    try:
        size = zip_path.stat().st_size
    except OSError:
        return None
    if size < 22:
        return None

    read_len = min(size, _EOCD_SEARCH_BYTES)
    try:
        with zip_path.open("rb") as fh:
            fh.seek(size - read_len)
            tail = fh.read(read_len)
            return _parse_eocd(tail, total_size=size, fh=fh)
    except (OSError, struct.error):
        return None


def _peek_from_bytes(blob: bytes) -> Optional[int]:
    size = len(blob)
    if size < 22:
        return None
    read_len = min(size, _EOCD_SEARCH_BYTES)
    tail = blob[size - read_len:]
    try:
        return _parse_eocd(tail, total_size=size, blob=blob)
    except struct.error:
        return None


def _parse_eocd(
    tail: bytes,
    *,
    total_size: int,
    fh=None,
    blob: Optional[bytes] = None,
) -> Optional[int]:
    """Locate the EOCD signature in ``tail`` and return total entries.

    Either ``fh`` (file handle, for ZIP64 follow-up reads) or ``blob``
    (in-memory zip, slice for ZIP64 follow-up reads) must be supplied
    when the EOCD reports ZIP64 sentinels.
    """
    eocd_off = tail.rfind(_EOCD_SIG)
    if eocd_off < 0 or eocd_off + 22 > len(tail):
        return None
    # entries-on-disk @ +8 (uint16); total-entries @ +10 (uint16)
    entries_disk, entries_total = struct.unpack_from(
        "<HH", tail, eocd_off + 8,
    )
    if entries_total != 0xFFFF and entries_disk != 0xFFFF:
        return entries_total

    # ZIP64 sentinel — try the locator (20 bytes BEFORE EOCD).
    loc_off = eocd_off - 20
    if loc_off < 0:
        return None
    if tail[loc_off:loc_off + 4] != _ZIP64_EOCD_LOCATOR_SIG:
        return None
    # ZIP64 EOCD record absolute offset @ locator +8 (uint64).
    zip64_eocd_off, = struct.unpack_from("<Q", tail, loc_off + 8)
    if zip64_eocd_off < 0 or zip64_eocd_off + 56 > total_size:
        return None
    if fh is not None:
        fh.seek(zip64_eocd_off)
        zip64_eocd = fh.read(56)
    else:
        assert blob is not None
        zip64_eocd = blob[zip64_eocd_off:zip64_eocd_off + 56]
    if zip64_eocd[:4] != _ZIP64_EOCD_SIG:
        return None
    # total-entries @ +32 (uint64) in the ZIP64 EOCD record.
    entries_total_64, = struct.unpack_from("<Q", zip64_eocd, 32)
    return entries_total_64


__all__ = [
    "DEFAULT_MAX_ENTRIES",
    "peek_total_entries",
]
