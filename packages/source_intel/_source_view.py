"""Shared comment/string-blanked source view for ``source_intel``.

source_intel scans the HOSTILE repo: a planted comment or string that
merely mentions ``static fn(``, a ``}`` that forges brace depth, a
privileged ``CAP_`` constant, an ``if (p) goto out;``, a downstream
size guard, or a fixed-size array declaration must never steer an
axis verdict or the prose handed to Stage D. core/audit routed the
identical problem through ``source_view.sanitized_view``; this module
is the package-wide adoption of that idiom (blanked spans become
spaces, newlines survive, so offsets and line numbers map 1:1 onto
the original text).

Hoisted out of ``adapter.py`` so ``analyze.py`` and ``render.py``
consume the SAME substrate — each previously grew its own raw-text
read, and the raw readers drifted into comment-forgeable behaviour
while their adapter twins were protected.

Reads are byte-capped: every consumer's ``None`` path is its
conservative direction, so an oversized (planted) file degrades
safely instead of becoming a memory sink.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

#: Byte ceiling on files admitted to the view. The whole file is read
#: and scanned per (path, mtime, size); a planted multi-GB "source
#: file" would otherwise turn every per-finding lexical check into a
#: memory/CPU sink. Real C files — amalgamations included (sqlite3.c
#: is ~9 MB) — fit comfortably. Oversized files return ``None``:
#: default grade, no static-ness, no privileged-cap evidence — always
#: the conservative direction.
MAX_SOURCE_BYTES = 16 * 1024 * 1024


def sanitized_source(file_path: str) -> str | None:
    """Comment/string-blanked view of ``file_path`` — the single
    lexical substrate for every helper in this package that mints or
    withholds a verdict-relevant fact from file text.

    Cached per (path, mtime, size) — repeated axis checks hit the
    same files. Returns ``None`` on read failure or when the file
    exceeds :data:`MAX_SOURCE_BYTES`.
    """
    try:
        st = Path(file_path).stat()
    except (OSError, ValueError):
        return None
    if st.st_size > MAX_SOURCE_BYTES:
        return None
    return _sanitized_source_cached(file_path, st.st_mtime_ns, st.st_size)


@lru_cache(maxsize=64)
def _sanitized_source_cached(
    file_path: str, _mtime_ns: int, _size: int,
) -> str | None:
    try:
        with Path(file_path).open(encoding="utf-8", errors="replace") as f:
            # Re-capped at read time: the file may have grown between
            # the stat gate and this read (target-writable trees).
            text = f.read(MAX_SOURCE_BYTES + 1)
    except OSError:
        return None
    if len(text) > MAX_SOURCE_BYTES:
        return None
    from core.audit.source_view import sanitized_view

    return sanitized_view(text, file_path)


def sanitized_lines(file_path: str) -> list[str] | None:
    """Line view of :func:`sanitized_source` (keepends, 1:1 lines)."""
    text = sanitized_source(file_path)
    return None if text is None else text.splitlines(keepends=True)


__all__ = ["MAX_SOURCE_BYTES", "sanitized_lines", "sanitized_source"]
