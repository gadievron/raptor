#!/usr/bin/env python3
"""SHA-256 hashing — single chokepoint for the codebase.

Four closed-form primitives:
  - sha256_tree(root, ...)  whole directory (filenames + contents)
  - sha256_file(path, ...)  single file, streamed in chunks
  - sha256_bytes(data)      bytes already in memory
  - sha256_string(s)        one-shot string hash

Every string-to-bytes conversion uses ``errors="surrogateescape"`` so
non-UTF-8 filenames (common on Linux) hash safely instead of raising
``UnicodeEncodeError``. For valid UTF-8 the encoding is identical.

For iterative accumulation across many inputs, use ``hashlib.sha256()``
directly — that's the right primitive and core.hash deliberately
doesn't wrap it.
"""

import hashlib
from pathlib import Path
from typing import Optional

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()

_FS_ENCODING = "utf-8"
_FS_ERRORS = "surrogateescape"


def sha256_tree(
    root: Path,
    max_file_size: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> str:
    """Hash a directory tree (filenames + contents).

    Args:
        root: Root directory to hash.
        max_file_size: Skip files larger than this. None = config default
            (RaptorConfig.MAX_FILE_SIZE_FOR_HASH). Pass 10**12 to disable.
        chunk_size: Read chunk size. None = config default
            (RaptorConfig.HASH_CHUNK_SIZE). Affects only read efficiency,
            not the digest.

    Returns:
        SHA256 hex digest of the directory tree.
    """
    if max_file_size is None:
        max_file_size = RaptorConfig.MAX_FILE_SIZE_FOR_HASH
    if chunk_size is None:
        chunk_size = RaptorConfig.HASH_CHUNK_SIZE
    # Pre-fix `chunk_size=1` (or any tiny value) was accepted
    # verbatim — a buggy caller passing 1 would byte-by-byte
    # read every file, turning a sub-second tree-hash into a
    # 1000x-slower I/O syscall storm. The slowdown was hard to
    # diagnose because the hash output was identical, only
    # wallclock changed. Floor at 4 KiB (the historical default
    # bottom; smaller than typical filesystem block size and any
    # real performance benefit ends well above this). Caller can
    # still tune larger; the floor only catches obvious
    # pathological inputs.
    chunk_size = max(int(chunk_size), 4096)

    h = hashlib.sha256()
    skipped = []
    # `os.walk(followlinks=False)` instead of `rglob` so we don't
    # follow symlinks during tree enumeration. Pre-fix `rglob`
    # follows symlinks by default on Python < 3.13. Three failure
    # modes:
    #   1. Symlink loop in the target tree → infinite enumeration,
    #      hash never completes.
    #   2. Symlink to a directory OUTSIDE root → that external
    #      tree gets included in the hash, so two trees that
    #      differ only in their out-of-tree symlink targets
    #      produce different hashes (or the same hash when
    #      content matches by coincidence). Cache validity is
    #      then incorrect across machines / mount layouts.
    #   3. Symlink to a sensitive file (`/etc/shadow` if
    #      readable, /proc/self/environ) — the contents flow
    #      into the hash AND into any error / debug message
    #      that surfaces the file. Inadvertent secret-in-hash.
    # os.walk + sorted yields the same canonical ordering as
    # the original sorted(rglob); use a per-dir sorted listing
    # so the resulting hash matches pre-fix for trees with no
    # symlinks (back-compat).
    import os as _os
    all_files: list[Path] = []
    for dirpath, dirnames, filenames in _os.walk(root, followlinks=False):
        # Sort in-place so iteration order matches sorted(rglob).
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            p = Path(dirpath) / name
            if p.is_symlink():
                # Skip leaf symlinks too — same threat model.
                continue
            all_files.append(p)
    # Final sort matches the original `sorted(root.rglob("*"))`
    # contract for callers that expected a particular ordering.
    all_files.sort()
    # Pre-fix the per-file gate was:
    #
    #   stat = p.stat()
    #   if stat.st_size > max_file_size: skip
    #   with p.open("rb") as f: ...
    #
    # Two leaks:
    #
    #   1. STAT-THEN-OPEN TOCTOU. Between p.stat() and
    #      p.open(), the file could grow (a concurrent writer
    #      under the target dir, or an attacker exploiting the
    #      window). The size check then fired on the OLD size
    #      while the open read reflected the NEW size, so a
    #      file the gate "skipped" actually had its full
    #      post-grow contents fed into the hash on the
    #      subsequent read.
    #   2. NO CUMULATIVE CAP. Each file's per-file size was
    #      bounded but the AGGREGATE bytes-hashed across the
    #      whole tree was unbounded. A target with 10K files of
    #      99% of max_file_size each consumed N×bound bytes of
    #      read I/O. Hashing-a-target-tree workflows on the
    #      sandbox path would hit the timeout, with no signal
    #      about which directory was responsible.
    #
    # Fix:
    #   * Open with O_NOFOLLOW (already won't follow symlinks
    #     because we filtered above; defence in depth).
    #   * fstat the OPEN FD — same kernel inode, no TOCTOU.
    #   * Track cumulative bytes hashed; abort with a logged
    #     warning when the cap is hit (default: 100x
    #     max_file_size — operators can set MAX_TREE_HASH_BYTES
    #     in config to override).
    import os as __os
    cumulative_cap = getattr(
        RaptorConfig, "MAX_TREE_HASH_BYTES",
        100 * (max_file_size if max_file_size is not None else 100 * 1024 * 1024),
    )
    cumulative_bytes = 0
    truncated = False
    for p in all_files:
        if not p.is_file():
            continue
        try:
            fd = __os.open(
                str(p),
                __os.O_RDONLY | __os.O_NOFOLLOW | getattr(__os, "O_CLOEXEC", 0),
            )
        except OSError:
            # ELOOP on race-introduced symlink, ENOENT on
            # race-removed file, EACCES on race-changed perms
            # — all best-effort skip.
            continue
        try:
            st = __os.fstat(fd)
            if (max_file_size is not None
                    and max_file_size < 10**12
                    and st.st_size > max_file_size):
                skipped.append(str(p.relative_to(root)))
                continue
            if cumulative_bytes + st.st_size > cumulative_cap:
                truncated = True
                break
            # surrogateescape round-trips non-UTF-8 bytes in filenames; plain
            # .encode() raises UnicodeEncodeError for those.
            h.update(p.relative_to(root).as_posix().encode(
                _FS_ENCODING, errors=_FS_ERRORS,
            ))
            with __os.fdopen(fd, "rb") as f:
                fd = -1  # fdopen now owns it; don't close twice
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    h.update(chunk)
                    cumulative_bytes += len(chunk)
        finally:
            if fd >= 0:
                try:
                    __os.close(fd)
                except OSError:
                    pass
    if skipped:
        logger.debug(f"Skipped {len(skipped)} large files during hashing")
    if truncated:
        logger.warning(
            f"sha256_tree: hit cumulative byte cap "
            f"({cumulative_cap} bytes) on {root}; "
            f"hash reflects partial tree only"
        )
    return h.hexdigest()


def _chunk_floor(chunk_size: int) -> int:
    """Floor chunk_size at 4 KiB — see sha256_tree comment for rationale."""
    return max(int(chunk_size), 4096)


def sha256_file(path: Path, chunk_size: Optional[int] = None) -> str:
    """Hash a single file, streaming in chunks (no full-file load).

    Use this in preference to ``hashlib.sha256(path.read_bytes())`` —
    streaming avoids OOM on multi-GB files.
    """
    if chunk_size is None:
        chunk_size = RaptorConfig.HASH_CHUNK_SIZE
    chunk_size = _chunk_floor(chunk_size)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Hash bytes already in memory."""
    return hashlib.sha256(data).hexdigest()


def sha256_string(s: str) -> str:
    """Hash a string (UTF-8, surrogateescape for raw-byte safety)."""
    return hashlib.sha256(
        s.encode(_FS_ENCODING, errors=_FS_ERRORS),
    ).hexdigest()
