"""Bounded source windows without retaining the rest of the file."""

from __future__ import annotations

from pathlib import Path

from core.source.contained import open_regular
from core.source.lines import split_lines

_CHUNK_BYTES = 64 * 1024


def _after_newlines(chunk: bytes, count: int) -> int:
    offset = 0
    for _ in range(count):
        offset = chunk.index(b"\n", offset) + 1
    return offset


def read_line_window_capped(
    path: Path, start: int, end: int, *, max_bytes: int,
) -> tuple[list[str], bool] | None:
    """Read the zero-based, half-open line window under a whole-file cap.

    Equivalent to split_lines(raw.decode('utf-8', errors='replace'))
    [start:end] for nonnegative bounds. Read through EOF or cap+1 even
    after finding the window: an oversized file or a later read error
    must still reject the snippet. No stat-based early acceptance and
    no retained state between calls. Memory is bounded by the selected
    bytes plus one chunk, rather than the entire file's decoded lines.
    """
    if start < 0 or end < 0 or max_bytes < 0:
        raise ValueError("window bounds and byte cap must be nonnegative")
    stream = open_regular(path, "rb")
    if stream is None:
        return None
    selected = bytearray()
    consumed = 0
    line = 0
    try:
        with stream:
            while chunk := stream.read(min(_CHUNK_BYTES, max_bytes + 1 - consumed)):
                consumed += len(chunk)
                if consumed > max_bytes:
                    return [], True
                if line >= end or end <= start:
                    continue
                breaks = chunk.count(b"\n")
                lower = 0
                if line < start:
                    lower = (_after_newlines(chunk, start - line)
                             if line + breaks >= start else len(chunk))
                upper = (_after_newlines(chunk, end - line)
                         if line + breaks >= end else len(chunk))
                if lower < upper:
                    selected.extend(chunk[lower:upper])
                line += breaks
    except OSError:
        return None
    return split_lines(selected.decode("utf-8", errors="replace")), False
