"""Line-range operations on source text.

Single chokepoint for the 1-indexed, inclusive-on-both-ends line
slicing convention used throughout RAPTOR (annotations, staleness,
context assembly, flow traces).  Centralises the ``max(0, start-1)``
/ ``min(len(lines), end)`` conversion so off-by-one bugs only need
fixing in one place.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "number_lines",
    "read_context",
    "read_lines",
    "slice_lines",
    "slice_text",
]


def slice_lines(
    lines: list[str], start_line: int, end_line: int,
) -> list[str]:
    """Slice a pre-split line list using RAPTOR's convention.

    ``start_line`` and ``end_line`` are 1-indexed and inclusive on
    both ends.  Invalid or out-of-range inputs return ``[]`` rather
    than raising — callers already handle empty results.
    """
    if start_line <= 0 or end_line < start_line:
        return []
    s = max(0, start_line - 1)
    e = min(len(lines), end_line)
    if s >= e:
        return []
    return lines[s:e]


def slice_text(
    text: str, start_line: int, end_line: int,
) -> str:
    """Slice raw text by line range, returning the joined snippet.

    Same convention as ``slice_lines`` but operates on unsplit text
    and returns a joined string.  Returns ``""`` for invalid/empty
    ranges.
    """
    result = slice_lines(text.splitlines(), start_line, end_line)
    return "\n".join(result) if result else ""


def read_lines(
    path: Path, start_line: int, end_line: int,
) -> str:
    """Read a line range from a file on disk.

    Returns ``""`` if the file is unreadable or the range is empty.
    Uses ``errors="replace"`` so non-UTF-8 bytes don't raise.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return slice_text(text, start_line, end_line)


def number_lines(
    lines: list[str], start_line: int = 1, *, width: int = 4,
) -> list[str]:
    """Add line-number prefixes to a list of lines.

    Returns ``["{n:>width}  {line}", ...]`` starting from
    *start_line*.  Used for LLM context and display formatting.
    """
    return [
        f"{start_line + i:>{width}}  {line}"
        for i, line in enumerate(lines)
    ]


def read_context(
    path: Path, center_line: int, margin: int,
) -> str:
    """Read a window of *margin* lines around *center_line*.

    Returns ``""`` on error.  The result is the raw text of lines
    ``[center_line - margin .. center_line + margin]``, clamped to
    file boundaries.
    """
    start = max(1, center_line - margin)
    end = center_line + margin
    return read_lines(path, start, end)
