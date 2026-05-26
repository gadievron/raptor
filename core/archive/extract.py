"""``extract_to_dir`` — safely unpack a Tier-1 archive into a directory.

Delegates to the hardened ``core.zip`` / ``core.tar`` primitives (which already
do zip-slip + bomb defense and hand back regular-files-only ``{name: bytes}``),
then writes those bytes to disk under ``dest``, re-validating each path stays
inside ``dest``. Only regular files are ever created — no symlinks or device
nodes — so symlink-escape attacks are impossible by construction.
"""

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from core.tar import (
    TarEntryCountExceeded,
    TarTotalBytesExceeded,
    extract_files_from_tar,
)
from core.zip import (
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_MEMBER_BYTES,
    ZipTotalBytesExceeded,
    extract_files_from_zip,
)

from .compression import decompress_single, looks_like_tar
from .detect import detect_format
from .errors import DecompressionLimitExceeded, UnsupportedArchive

logger = logging.getLogger(__name__)

DEFAULT_MAX_TOTAL_BYTES = 2 << 30  # 2 GiB summed across all extracted members
DEFAULT_MAX_FILES = DEFAULT_MAX_ENTRIES

# Compression suffixes stripped to name a single decompressed file.
_SINGLE_SUFFIXES = (".gz", ".xz", ".bz2", ".zst")


def _keep_files(info: Any) -> Optional[str]:
    """Selector for the zip/tar primitives: keep regular files, skip dirs.

    Handles both ``ZipInfo`` (``.filename`` + ``.is_dir()``) and ``TarInfo``
    (``.name``; the tar primitive already filtered to ``isfile()``)."""
    is_dir = getattr(info, "is_dir", None)
    if callable(is_dir) and is_dir():
        return None
    return getattr(info, "filename", None) or getattr(info, "name", None)


def _single_file_name(src: Path) -> str:
    """Filename for a single decompressed file: the archive name minus its
    compression suffix (``notes.txt.gz`` → ``notes.txt``), else ``<name>.out``."""
    name = src.name
    low = name.lower()
    for suf in _SINGLE_SUFFIXES:
        if low.endswith(suf):
            return name[: -len(suf)] or "decompressed.out"
    return name + ".out"


def _safe_dest_path(dest_root: Path, member_name: str) -> Optional[Path]:
    """Resolve ``member_name`` under ``dest_root`` or return None if it escapes.

    The primitives already reject traversal; this is the write-boundary
    re-check (defense in depth) so we can never write outside ``dest_root``.
    Returns None for any name that escapes OR can't be resolved at all (e.g. an
    embedded NUL/control byte that makes resolve() raise ValueError) — such a
    member is simply dropped rather than crashing extraction.
    """
    rel = member_name.lstrip("/\\")
    try:
        root = dest_root.resolve()
        target = (root / rel).resolve()
        target.relative_to(root)
    except (OSError, ValueError):
        return None
    return target


def _write_members(members: Dict[str, bytes], dest: Path,
                   max_total: int, max_files: int) -> Dict[str, int]:
    if len(members) > max_files:
        raise DecompressionLimitExceeded(
            f"archive has {len(members)} files — exceeds cap of {max_files}")
    total = 0
    written = 0
    for name, data in members.items():
        total += len(data)
        if total > max_total:
            raise DecompressionLimitExceeded(
                f"archive exceeds {max_total} bytes extracted — refusing as bomb")
        target = _safe_dest_path(dest, name)
        if target is None:
            logger.warning("core.archive: dropping out-of-tree member %r", name)
            continue
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(data)
        except (OSError, ValueError) as e:
            # Never let one pathological member (an OS-unwritable name that
            # slipped the safety gate, a disk error) crash extraction of
            # attacker-controlled input — skip it and carry on.
            logger.warning("core.archive: skipping unwritable member %r (%s)", name, e)
            continue
        written += 1
    return {"files": written, "bytes": total}


def extract_to_dir(path, dest, *,
                   max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
                   max_files: int = DEFAULT_MAX_FILES,
                   max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES) -> Dict[str, Any]:
    """Extract a Tier-1 archive (``path``) into ``dest``; return a summary dict
    ``{"format", "files", "bytes"}``.

    Tier 1: zip, tar, ``.tar.{gz,xz,bz2}``, and single-file gz/bz2/xz/zst.
    Raises ``UnsupportedArchive`` for unknown formats and
    ``DecompressionLimitExceeded`` / ``ArchiveError`` on unsafe or corrupt input.
    """
    src = Path(path)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    fmt = detect_format(src)
    if fmt is None:
        raise UnsupportedArchive(f"{src} is not a recognised archive")

    # The primitives now enforce ``max_total_bytes`` as a RUNNING sum (and tar
    # an entry count), so peak memory is bounded to ~max_total instead of
    # entries×member_bytes (~640 GiB worst case). Their bomb exceptions are
    # mapped to DecompressionLimitExceeded.
    try:
        if fmt == "zip":
            members = extract_files_from_zip(
                src, selector=_keep_files, max_member_bytes=max_member_bytes,
                max_entry_count=max_files, max_total_bytes=max_total_bytes)
        elif fmt == "tar":
            members = extract_files_from_tar(
                src.read_bytes(), selector=_keep_files, mode="r:*",
                max_member_bytes=max_member_bytes,
                max_total_bytes=max_total_bytes, max_entry_count=max_files)
        else:
            # gz/bz2/xz/zst: a compressed tar OR a single compressed file.
            raw = decompress_single(src, fmt, max_bytes=max_total_bytes)
            if looks_like_tar(raw):
                members = extract_files_from_tar(
                    raw, selector=_keep_files, mode="r:",
                    max_member_bytes=max_member_bytes,
                    max_total_bytes=max_total_bytes, max_entry_count=max_files)
            else:
                members = {_single_file_name(src): raw}
    except (ZipTotalBytesExceeded, TarTotalBytesExceeded, TarEntryCountExceeded) as e:
        raise DecompressionLimitExceeded(str(e)) from e

    stats = _write_members(members, dest, max_total_bytes, max_files)
    stats["format"] = fmt
    return stats
