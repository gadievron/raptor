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
  * :func:`peek_eocd` — read EOCD from a path (Path / str) or bytes,
    return an :class:`EocdSummary` (declared total entry count AND
    declared central-directory size) or ``None`` if parsing failed.
  * :func:`peek_total_entries` — entry-count-only convenience wrapper.
  * :func:`bomb_shaped_reason` — cross-check an :class:`EocdSummary`
    against the entry cap AND the central-directory size bounds;
    returns a human-readable rejection reason or ``None``.
  * :data:`DEFAULT_MAX_ENTRIES` — the conventional cap (10 000).
    Legitimate raptor archives have << 1000 entries; CodeQL DBs and
    third-party wheels are well under 10k.

The central-directory size cross-check exists because the declared
entry count alone is forgeable independently of the CD:
``zipfile.ZipFile.__init__`` reads ``cd_size`` bytes and parses
records from them until the buffer is exhausted, IGNORING the
declared count — so an archive with a huge real central directory
and an EOCD patched to declare a tiny count sails past a count-only
pre-flight and still costs the full CD materialisation. Bounding
``cd_size`` (per declared entry, plus an absolute cap) closes that
bypass while staying far above anything a legitimate archive needs.

ZIP64 sentinels (``entries_total == 0xFFFF``) follow the locator
back to the ZIP64 EOCD record at the absolute offset stored in the
locator. Malformed / unparseable archives return ``None`` so the
caller can fall through to the normal ZipFile() path (which will
raise ``BadZipFile`` for genuinely broken inputs).
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)


# Cap on a zip archive's entry count. 10 000 is generous for every
# real consumer — raptor's own project exports have a few hundred
# entries, CodeQL DB archives a few thousand, PyPI sdists tens to
# hundreds. Above 10k the bomb hypothesis dominates the data one.
DEFAULT_MAX_ENTRIES = 10_000

# Sane average size for one central-directory record, used to bound
# the declared cd-size against the declared entry count. A record is
# a 46-byte fixed header plus the member name (rarely > a few hundred
# bytes) plus small extra fields (ZIP64 extras are ~32 bytes; unicode
# path extras similar). 4 KiB per entry is ~20x any realistic average
# while still catching a forged small-count EOCD in front of a huge
# real central directory (whose per-declared-entry ratio is enormous).
MAX_CD_BYTES_PER_ENTRY = 4096

# Absolute cap on the declared central-directory size — bounds the
# construction-time RSS ``zipfile.ZipFile.__init__`` pays reading the
# CD regardless of how the count/size ratio is gamed. 64 MiB holds
# hundreds of thousands of spec-typical records; every legitimate
# raptor consumer's archives carry CDs in the KB-to-low-MB range.
DEFAULT_MAX_CD_BYTES = 64 * 1024 * 1024


class EocdSummary(NamedTuple):
    """Declared totals read from a zip's EOCD (or ZIP64 EOCD) record.

    Both fields are attacker-declared bytes — callers must treat them
    as claims to cross-check (see :func:`bomb_shaped_reason`), never
    as truth.
    """

    entries_total: int
    cd_size: int


def bomb_shaped_reason(
    summary: EocdSummary,
    *,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_cd_bytes: int = DEFAULT_MAX_CD_BYTES,
    max_cd_bytes_per_entry: int = MAX_CD_BYTES_PER_ENTRY,
) -> str | None:
    """Cross-check the declared EOCD totals; return a rejection
    reason when the archive is bomb-shaped, else ``None``.

    Three gates:

    * declared entry count over ``max_entries`` — the classic
      many-entries bomb;
    * declared cd-size exceeding ``max_cd_bytes_per_entry`` x the
      declared entry count — a forged small count in front of a huge
      real central directory (``ZipFile`` parses the CD until the
      ``cd_size`` buffer is exhausted, ignoring the count);
    * declared cd-size over the absolute ``max_cd_bytes`` cap —
      bounds construction-time RSS whatever the ratio.
    """
    if summary.entries_total > max_entries:
        return (
            f"zip declares {summary.entries_total} entries in EOCD — "
            f"exceeds cap of {max_entries}; refusing as zip-bomb shape"
        )
    if summary.cd_size > summary.entries_total * max_cd_bytes_per_entry:
        return (
            f"zip declares a {summary.cd_size}-byte central directory "
            f"for {summary.entries_total} entries in EOCD — exceeds "
            f"{max_cd_bytes_per_entry} bytes/entry; refusing as "
            f"zip-bomb shape (forged EOCD entry count)"
        )
    if summary.cd_size > max_cd_bytes:
        return (
            f"zip declares a {summary.cd_size}-byte central directory "
            f"in EOCD — exceeds the {max_cd_bytes}-byte cap; refusing "
            f"as zip-bomb shape"
        )
    return None

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


def peek_eocd(
    source: Path | str | bytes,
) -> EocdSummary | None:
    """Read the EOCD pre-flight from ``source`` and return the zip's
    declared totals (entry count + central-directory size), or
    ``None`` on unparseable EOCD.

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
    parse cleanly, :func:`bomb_shaped_reason` over the returned
    summary fires the caller's gate.
    """
    if isinstance(source, (bytes, bytearray)):
        return _peek_from_bytes(bytes(source))
    return _peek_from_path(Path(source))


def peek_total_entries(
    source: Path | str | bytes,
) -> int | None:
    """Entry-count-only convenience wrapper around :func:`peek_eocd`.

    Prefer :func:`peek_eocd` + :func:`bomb_shaped_reason` for gating —
    the count alone is forgeable independently of the central
    directory it claims to describe.
    """
    summary = peek_eocd(source)
    return summary.entries_total if summary is not None else None


def _peek_from_path(zip_path: Path) -> EocdSummary | None:
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


def _peek_from_bytes(blob: bytes) -> EocdSummary | None:
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
    blob: bytes | None = None,
) -> EocdSummary | None:
    """Locate the EOCD signature in ``tail`` and return the declared
    totals (entry count + central-directory size).

    Either ``fh`` (file handle, for ZIP64 follow-up reads) or ``blob``
    (in-memory zip, slice for ZIP64 follow-up reads) must be supplied
    when the EOCD reports ZIP64 sentinels.
    """
    eocd_off = tail.rfind(_EOCD_SIG)
    if eocd_off < 0 or eocd_off + 22 > len(tail):
        return None
    # entries-on-disk @ +8 (uint16); total-entries @ +10 (uint16);
    # cd-size @ +12 (uint32)
    entries_disk, entries_total, cd_size = struct.unpack_from(
        "<HHI", tail, eocd_off + 8,
    )
    if (entries_total != 0xFFFF and entries_disk != 0xFFFF
            and cd_size != 0xFFFFFFFF):
        return EocdSummary(entries_total=entries_total, cd_size=cd_size)

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
        # Defensive: caller invariant is that exactly one of {fh, blob}
        # is non-None. Use explicit raise rather than assert so the
        # check survives `python -O`.
        if blob is None:
            msg = "eocd: internal invariant — fh and blob both None"
            raise RuntimeError(msg)
        zip64_eocd = blob[zip64_eocd_off:zip64_eocd_off + 56]
    if zip64_eocd[:4] != _ZIP64_EOCD_SIG:
        return None
    # total-entries @ +32 (uint64); cd-size @ +40 (uint64) in the
    # ZIP64 EOCD record.
    entries_total_64, cd_size_64 = struct.unpack_from(
        "<QQ", zip64_eocd, 32,
    )
    return EocdSummary(entries_total=entries_total_64, cd_size=cd_size_64)


__all__ = [
    "DEFAULT_MAX_CD_BYTES",
    "DEFAULT_MAX_ENTRIES",
    "EocdSummary",
    "MAX_CD_BYTES_PER_ENTRY",
    "bomb_shaped_reason",
    "peek_eocd",
    "peek_total_entries",
]
