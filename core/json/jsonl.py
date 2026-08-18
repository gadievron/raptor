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
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


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
    symlink (O_NOFOLLOW) — and ``TypeError`` when *record* is not JSON
    serialisable. Callers with a best-effort contract catch ``OSError``
    themselves, preserving their own logging conventions.
    """
    separators = (",", ":") if compact else None
    line = (
        json.dumps(record, sort_keys=sort_keys, separators=separators) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_NOFOLLOW | _O_CLOEXEC
    fd = os.open(str(path), flags, mode)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def load_jsonl(path: str | Path) -> list[Any]:
    """Read back a JSONL trail as a list of parsed records.

    Best-effort: a missing, unreadable, or symlinked file loads as
    ``[]`` (logged at debug); blank and malformed lines are skipped so
    a truncated final line (writer killed mid-append) doesn't lose the
    well-formed records before it. Callers that only want objects
    filter with ``isinstance(rec, dict)`` on the result.
    """
    flags = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC
    try:
        fd = os.open(str(path), flags)
    except OSError:
        # ENOENT (no trail yet) and ELOOP (symlink rejected) both mean
        # "nothing trustworthy to read".
        logger.debug("load_jsonl: cannot open %s", path, exc_info=True)
        return []
    records: list[Any] = []
    try:
        f = os.fdopen(fd, "r", encoding="utf-8")
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        logger.debug("load_jsonl: cannot read %s", path, exc_info=True)
        return records
    with f:
        try:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError:
            logger.debug("load_jsonl: read failed for %s", path, exc_info=True)
    return records
