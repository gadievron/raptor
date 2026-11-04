"""Bounded source windows without retaining the rest of the file."""

from __future__ import annotations

from pathlib import Path

from core.source.contained import DEFAULT_MAX_SOURCE_CHARS, open_regular
from core.source.lines import split_lines

_CHUNK_BYTES = 64 * 1024
_CHUNK_CHARS = 64 * 1024


def _after_newlines(chunk: bytes, count: int, offset: int = 0) -> int:
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
                # Reuse the lower offset instead of rescanning its prefix.
                upper = (_after_newlines(chunk, end - max(line, start), lower)
                         if line + breaks >= end else len(chunk))
                if lower < upper:
                    selected.extend(chunk[lower:upper])
                line += breaks
    except OSError:
        return None
    return split_lines(selected.decode("utf-8", errors="replace")), False


def _after_text_newlines(chunk: str, count: int, offset: int = 0) -> int:
    for _ in range(count):
        offset = chunk.index("\n", offset) + 1
    return offset


def read_text_line_window_capped(
    path: Path, start: int, end: int, *, max_chars: int = DEFAULT_MAX_SOURCE_CHARS,
) -> tuple[list[str], bool] | None:
    """Window over read_text_capped(..., newline="")'s visible prefix.

    Unlike the byte-capped reader, oversize input returns a truncated
    prefix. Probe max_chars+1 decoded characters, retaining only the
    requested zero-based/half-open window. Match the legacy last-partial-
    line trimming (and its no-newline exception) before splitting lines.
    Read through the character probe even after finding the window so
    later read errors and the truncation flag retain their meaning.
    """
    if start < 0 or end < 0 or max_chars < 0:
        raise ValueError("window bounds and character cap must be nonnegative")
    stream = open_regular(path, "r", encoding="utf-8", errors="replace", newline="")
    if stream is None:
        return None
    parts: list[str] = []
    consumed = 0
    line = 0
    truncated = False
    try:
        with stream:
            while chunk := stream.read(min(_CHUNK_CHARS, max_chars + 1 - consumed)):
                allowed = max_chars - consumed
                consumed += len(chunk)
                truncated = consumed > max_chars
                if truncated:
                    chunk = chunk[:allowed]
                if line < end and end > start:
                    breaks = chunk.count("\n")
                    lower = 0
                    if line < start:
                        lower = (_after_text_newlines(chunk, start - line)
                                 if line + breaks >= start else len(chunk))
                    # Reuse the lower offset instead of rescanning its prefix.
                    upper = (_after_text_newlines(chunk, end - max(line, start), lower)
                             if line + breaks >= end else len(chunk))
                    if lower < upper:
                        parts.append(chunk[lower:upper])
                    line += breaks
                if truncated:
                    break
    except OSError:
        return None
    selected = "".join(parts)
    if truncated and line > 0 and start <= line < end:
        # The cap cut the currently selected line. The preceding newline
        # can be before this window, in which case none of it is visible.
        selected = selected.rsplit("\n", 1)[0] + "\n" if "\n" in selected else ""
    return split_lines(selected), truncated
