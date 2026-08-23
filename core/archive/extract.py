"""``extract_to_dir`` — safely unpack a Tier-1 archive into a directory.

Delegates to the hardened ``core.zip`` / ``core.tar`` primitives (which already
do zip-slip + bomb defense and filter to regular files), writing member bytes
to disk under ``dest`` and re-validating each path stays inside ``dest``. Tar
paths stream: members go straight from the primitive to a disk-writing sink,
so peak memory is one member — never the aggregate budget. Only regular files
are ever created — no symlinks or device nodes — so symlink-escape attacks are
impossible by construction.
"""

import logging
import tarfile
from pathlib import Path
from typing import Any

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

from itertools import chain

from .compression import _TAR_MAGIC_OFFSET, iter_decompressed, looks_like_tar
from .detect import detect_format
from .errors import ArchiveError, DecompressionLimitExceeded, UnsupportedArchive

logger = logging.getLogger(__name__)

DEFAULT_MAX_TOTAL_BYTES = 2 << 30  # 2 GiB summed across all extracted members
DEFAULT_MAX_FILES = DEFAULT_MAX_ENTRIES

# Compression suffixes stripped to name a single decompressed file.
_SINGLE_SUFFIXES = (".gz", ".xz", ".bz2", ".zst")


def _keep_files(info: Any) -> str | None:
    """Selector for the zip/tar primitives: keep regular files, skip dirs.

    Handles both ``ZipInfo`` (``.filename`` + ``.is_dir()``) and ``TarInfo``
    (``.name``; the tar primitive already filtered to ``isfile()``)."""
    is_dir = getattr(info, "is_dir", None)
    if callable(is_dir) and is_dir():
        return None
    return getattr(info, "filename", None) or getattr(info, "name", None)


def _iter_file_chunks(fh, chunk_bytes: int = 1 << 20):
    """Yield ``fh`` in bounded chunks so the tar primitive can stream the
    archive without the whole file ever being resident in memory."""
    return iter(lambda: fh.read(chunk_bytes), b"")


def _single_file_name(src: Path) -> str:
    """Filename for a single decompressed file: the archive name minus its
    compression suffix (``notes.txt.gz`` → ``notes.txt``), else ``<name>.out``."""
    name = src.name
    low = name.lower()
    for suf in _SINGLE_SUFFIXES:
        if low.endswith(suf):
            return name[: -len(suf)] or "decompressed.out"
    return name + ".out"


def _safe_dest_path(dest_root: Path, member_name: str) -> Path | None:
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


def _write_members(members: dict[str, bytes], dest: Path,
                   max_total: int, max_files: int) -> dict[str, int]:
    if len(members) > max_files:
        msg = f"archive has {len(members)} files — exceeds cap of {max_files}"
        raise DecompressionLimitExceeded(msg)
    total = 0
    written = 0
    dropped = 0
    for name, data in members.items():
        total += len(data)
        if total > max_total:
            msg = f"archive exceeds {max_total} bytes extracted — refusing as bomb"
            raise DecompressionLimitExceeded(msg)
        target = _safe_dest_path(dest, name)
        if target is None:
            logger.warning("core.archive: dropping out-of-tree member %r", name)
            dropped += 1
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
            dropped += 1
            continue
        written += 1
    return {"files": written, "bytes": total, "dropped": dropped}


class _DiskSink:
    """Streams selected members straight to disk with the same running
    byte / file-count budget ``_write_members`` enforces — but the
    member bytes never accumulate in a dict, so peak memory is one
    member (bounded by ``max_member_bytes``) instead of the whole
    archive's ``max_total`` (2 GiB by default)."""

    def __init__(self, dest: Path, max_total: int, max_files: int):
        self._dest = dest
        self._max_total = max_total
        self._max_files = max_files
        self.total = 0
        self.written = 0
        self.dropped = 0
        self._seen = 0

    def __call__(self, name: str, data: bytes) -> None:
        self._seen += 1
        if self._seen > self._max_files:
            raise DecompressionLimitExceeded(
                f"archive has {self._seen} files — exceeds cap of "
                f"{self._max_files}")
        self.total += len(data)
        if self.total > self._max_total:
            raise DecompressionLimitExceeded(
                f"archive exceeds {self._max_total} bytes extracted — "
                f"refusing as bomb")
        target = _safe_dest_path(self._dest, name)
        if target is None:
            logger.warning("core.archive: dropping out-of-tree member %r", name)
            self.dropped += 1
            return
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(data)
        except (OSError, ValueError) as e:
            # Same tolerance as _write_members: one pathological member
            # must not crash extraction of attacker-controlled input.
            logger.warning(
                "core.archive: skipping unwritable member %r (%s)", name, e)
            self.dropped += 1
            return
        self.written += 1

    def stats(self) -> dict[str, int]:
        return {"files": self.written, "bytes": self.total,
                "dropped": self.dropped}


def _write_single_file(chunks, src: Path, dest: Path) -> dict[str, int]:
    """Stream a decompressed single file to ``dest`` chunk by chunk —
    the cap lives in the ``iter_decompressed`` generator feeding us."""
    name = _single_file_name(src)
    target = _safe_dest_path(dest, name)
    if target is None:  # pragma: no cover — plain basename never escapes
        raise UnsupportedArchive(f"cannot derive a safe name for {src}")
    total = 0
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as fh:
        for chunk in chunks:
            fh.write(chunk)
            total += len(chunk)
    return {"files": 1, "bytes": total, "dropped": 0}


def extract_to_dir(path, dest, *,
                   max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
                   max_files: int = DEFAULT_MAX_FILES,
                   max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES) -> dict[str, Any]:
    """Extract a Tier-1 archive (``path``) into ``dest``; return a summary dict
    ``{"format", "files", "bytes", "dropped"}`` (``dropped`` counts members
    rejected at the write boundary — out-of-tree or unwritable names).

    Tier 1: zip, tar, ``.tar.{gz,xz,bz2}``, and single-file gz/bz2/xz/zst.
    Raises ``UnsupportedArchive`` for unknown formats and
    ``DecompressionLimitExceeded`` / ``ArchiveError`` on unsafe or corrupt
    input — a corrupt or truncated tar REFUSES instead of returning an
    empty "success" summary that downstream consumers would treat as a
    complete extraction.
    """
    src = Path(path)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    fmt = detect_format(src)
    if fmt is None:
        msg = f"{src} is not a recognised archive"
        raise UnsupportedArchive(msg)

    # Memory posture: every tar-shaped path streams — the archive is
    # fed to the primitive in bounded chunks AND each selected member
    # is handed to a disk-writing sink as soon as it is read, so peak
    # memory is one member (max_member_bytes), never the aggregate
    # max_total_bytes (2 GiB by default — previously held wholesale in
    # a dict before any write, ~3 GiB stacked with the compressed-tar
    # buffer). Zip is the exception: its central directory lives at
    # the end of the archive so the hardened primitive is seek-based
    # and returns member bytes; its own running ``max_total_bytes``
    # cap bounds that dict. The primitives' bomb exceptions are mapped
    # to DecompressionLimitExceeded.
    sink = _DiskSink(dest, max_total_bytes, max_files)
    try:
        if fmt == "zip":
            members = extract_files_from_zip(
                src, selector=_keep_files, max_member_bytes=max_member_bytes,
                max_entry_count=max_files, max_total_bytes=max_total_bytes)
            stats = _write_members(members, dest, max_total_bytes, max_files)
        elif fmt == "tar":
            # Stream the on-disk tar member-by-member ("r|*"). read_bytes()
            # would materialise the whole archive in RAM before any cap
            # applies — the caps below only bound bytes already read.
            with Path(src).open("rb") as fh:
                extract_files_from_tar(
                    _iter_file_chunks(fh), selector=_keep_files, mode="r|*",
                    max_member_bytes=max_member_bytes,
                    max_total_bytes=max_total_bytes, max_entry_count=max_files,
                    sink=sink)
            stats = sink.stats()
        else:
            # gz/bz2/xz/zst: a compressed tar OR a single compressed
            # file. Stream-decompress either way; buffer only enough
            # head bytes to sniff the tar magic at offset 257.
            chunks = iter_decompressed(src, fmt, max_bytes=max_total_bytes)
            head = b""
            for chunk in chunks:
                head += chunk
                if len(head) > _TAR_MAGIC_OFFSET + 8:
                    break
            if looks_like_tar(head):
                extract_files_from_tar(
                    chain([head], chunks), selector=_keep_files, mode="r|",
                    max_member_bytes=max_member_bytes,
                    max_total_bytes=max_total_bytes, max_entry_count=max_files,
                    sink=sink)
                stats = sink.stats()
            else:
                stats = _write_single_file(chain([head], chunks), src, dest)
    except (ZipTotalBytesExceeded, TarTotalBytesExceeded, TarEntryCountExceeded) as e:
        raise DecompressionLimitExceeded(str(e)) from e
    except tarfile.TarError as e:
        # TarOpenError (unreadable archive) + mid-stream ReadError on a
        # truncated tar. Both REFUSE, typed, instead of leaking raw
        # tarfile exceptions or converting corruption into empty success.
        raise ArchiveError(f"corrupt or unreadable tar archive: {e}") from e

    stats["format"] = fmt
    return stats
