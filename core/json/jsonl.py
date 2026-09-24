"""Append-only JSONL trail helpers.

RAPTOR keeps several append-only audit trails (``suppressions.jsonl``,
``promotion-alarms.jsonl``, ``.audit-log.jsonl``, sandbox denial logs,
coverage manifests). Each used to re-implement "append one JSON line"
with inconsistent hardening: some writers used ``O_NOFOLLOW`` (the
sandbox observe log), others opened the path bare — so a symlink
planted at a predictable trail path inside a writable run dir was
followed, redirecting the append to an arbitrary file.

This module is the one hardened implementation:

- ``O_APPEND`` + a single ``os.write`` keeps concurrent writers
  line-atomic (POSIX guarantees atomic appends for writes below
  PIPE_BUF-ish sizes on regular files; every record here is small).
- ``O_NOFOLLOW`` refuses symlinked trail paths (fails with ELOOP)
  on both the write and the read side, mirroring the trust contract
  of ``core/sandbox/observe_profile._iter_records``.
- ``O_CLOEXEC`` keeps the fd out of spawned children.
- ``O_NONBLOCK`` plus a post-open ``fstat`` regularity check on the
  write side refuses a planted FIFO: an ``O_WRONLY`` open of a
  reader-less FIFO otherwise blocks the appending process forever,
  and a FIFO with a reader would silently swallow the record. Same
  discipline as the coverage journal's lock open.

``append_jsonl`` raises ``OSError`` (including ELOOP for a rejected
symlink); best-effort callers wrap it. ``load_jsonl`` is best-effort
by contract: missing/unreadable/symlinked files load as ``[]`` and
malformed lines are skipped, because a partial trailing line (writer
killed mid-append) must not lose every well-formed record before it.
"""

from __future__ import annotations

import json
import logging
import os
import stat as _stat
from typing import Any, TYPE_CHECKING

from core.json.utils import _loads, _reject_non_finite

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def append_jsonl(
    path: str | Path,
    record: Any,
    *,
    sort_keys: bool = False,
    compact: bool = False,
    mode: int = 0o644,
) -> None:
    """Append *record* as one JSON line to the trail at *path*.

    ``sort_keys`` makes the emitted line key-stable (useful when the
    trail is diffed or hashed); ``compact`` drops whitespace after
    separators (``json.dumps(separators=(",", ":"))``).

    Raises ``OSError`` on I/O failure — notably ELOOP when *path* is a
    symlink (O_NOFOLLOW), ENXIO when it is a reader-less FIFO
    (O_NONBLOCK), and a regularity refusal when the opened fd is any
    other non-regular file — ``TypeError`` when *record* is not JSON
    serialisable, and ``ValueError`` when it contains a non-finite
    float (``allow_nan=False``): the read side skips NaN/Infinity
    lines as malformed on both backends, so letting a writer emit
    them would silently lose the record on the NEXT read. Failing
    loudly at write time is the same parity rule ``save_json``
    applies. Callers with a best-effort contract catch ``OSError``
    themselves, preserving their own logging conventions.
    """
    separators = (",", ":") if compact else None
    line = (
        json.dumps(
            record, sort_keys=sort_keys, separators=separators,
            allow_nan=False,
        ) + "\n"
    ).encode("utf-8")
    # O_NONBLOCK: trail paths live inside run dirs a sandboxed child
    # holds (or held) write on — an O_WRONLY open of a planted
    # reader-less FIFO would otherwise wedge the appender forever.
    # With the flag it fails fast (ENXIO); a FIFO that HAS a reader
    # opens fine, so the post-open fstat refusal below is the second
    # half of the same defence (O_NONBLOCK is a no-op on the regular
    # files every legitimate trail is).
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_APPEND
        | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK
    )
    fd = os.open(str(path), flags, mode)
    try:
        if not _stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(
                f"refusing to append to {path}: not a regular file "
                "(planted FIFO/device at the trail path?)",
            )
        # ``os.write`` may return a SHORT count (RLIMIT_FSIZE, quota,
        # signal after partial progress). Ignoring it reported a
        # truncated record as success — and the read side deliberately
        # skips malformed lines, so the audit-trail record vanished
        # silently. Loop until every byte lands; zero progress raises
        # instead of spinning. Records are far below PIPE_BUF-ish
        # sizes, so the first write is whole-line in practice and
        # concurrent-append line-atomicity is unaffected.
        view = memoryview(line)
        written = 0
        while written < len(view):
            n = os.write(fd, view[written:])
            if n <= 0:
                raise OSError(
                    f"short write to {path}: os.write returned {n}",
                )
            written += n
    finally:
        os.close(fd)


def load_jsonl(
    path: str | Path,
    *,
    max_line_bytes: int | None = None,
    max_total_bytes: int | None = None,
) -> list[Any]:
    """Read back a JSONL trail as a list of parsed records.

    Best-effort: a missing, unreadable, or symlinked file loads as
    ``[]`` (logged at debug); blank and malformed lines are skipped so
    a truncated final line (writer killed mid-append) doesn't lose the
    well-formed records before it. Invalid UTF-8 counts as malformed
    at LINE granularity: the file is read as bytes and each line is
    decoded independently, so one corrupt byte (torn write, foreign
    writer) skips only its own line instead of raising
    ``UnicodeDecodeError`` out of the strict text-mode read and losing
    every well-formed record in the trail. Callers that only want
    objects filter with ``isinstance(rec, dict)`` on the result.

    Byte budgets (keyword-only, ``None`` = historical unbounded):

    - ``max_total_bytes``: ``fstat`` size gate on the opened fd BEFORE
      any read; an oversize trail loads as ``[]`` with a warning —
      nothing is buffered.
    - ``max_line_bytes``: an over-long line is skipped like a
      malformed one. The check runs after the line is materialised,
      so pair it with ``max_total_bytes`` for a hard memory bound.

    Lines parse through the shared ``core.json`` backend (orjson when
    installed — trail loops are its best-measured win). Non-finite
    constants (``NaN``/``Infinity``) make a line malformed on BOTH
    backends: orjson rejects them natively, and the stdlib branch is
    pinned to the same behaviour via ``_reject_non_finite`` so which
    records survive never depends on which backend is installed.
    (``append_jsonl`` refuses to emit them — ``allow_nan=False`` —
    so only a foreign writer can put one in a trail.)
    """
    flags = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC
    try:
        fd = os.open(str(path), flags)
    except OSError:
        # ENOENT (no trail yet) and ELOOP (symlink rejected) both mean
        # "nothing trustworthy to read".
        logger.debug("load_jsonl: cannot open %s", path, exc_info=True)
        return []
    if max_total_bytes is not None:
        try:
            size = os.fstat(fd).st_size
        except OSError:
            size = None
        if size is not None and size > max_total_bytes:
            try:
                os.close(fd)
            except OSError:
                pass
            logger.warning(
                "load_jsonl: refusing oversize trail %s "
                "(%d bytes > max_total_bytes=%d)",
                path, size, max_total_bytes,
            )
            return []
    records: list[Any] = []
    try:
        f = os.fdopen(fd, "rb")
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        logger.debug("load_jsonl: cannot read %s", path, exc_info=True)
        return records
    with f:
        try:
            oversize_lines = 0
            invalid_lines = 0
            # File iteration splits on ``\n`` only; ``splitlines`` on
            # each chunk restores the bare-``\r`` separators the old
            # text-mode universal-newlines read accepted (foreign
            # writers only — no RAPTOR writer emits them). CRLF and
            # plain-``\n`` chunks yield exactly one segment each.
            for raw_bytes in f:
                for line_bytes in raw_bytes.splitlines():
                    if (
                        max_line_bytes is not None
                        and len(line_bytes) > max_line_bytes
                    ):
                        oversize_lines += 1
                        continue
                    try:
                        raw = line_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        invalid_lines += 1
                        continue
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        records.append(
                            _loads(line, parse_constant=_reject_non_finite))
                    except ValueError:
                        # json.JSONDecodeError (both backends) and the
                        # non-finite rejection are ValueError subclasses.
                        continue
                    except RecursionError:
                        # Python <= 3.13's stdlib parser is recursive,
                        # so a deeply-nested line raises RecursionError
                        # instead of a decode error — same best-effort
                        # skip, or the foreign writer's bomb line kills
                        # the whole trail.
                        continue
        except OSError:
            logger.debug("load_jsonl: read failed for %s", path, exc_info=True)
        if oversize_lines:
            logger.warning(
                "load_jsonl: skipped %d line(s) over max_line_bytes=%d in %s",
                oversize_lines, max_line_bytes, path,
            )
        if invalid_lines:
            logger.warning(
                "load_jsonl: skipped %d invalid-UTF-8 line(s) in %s",
                invalid_lines, path,
            )
    return records
