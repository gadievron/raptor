"""Line-range operations on source text.

Single chokepoint for the 1-indexed, inclusive-on-both-ends line
slicing convention used throughout RAPTOR (annotations, staleness,
context assembly, flow traces).  Centralises the ``max(0, start-1)``
/ ``min(len(lines), end)`` conversion so off-by-one bugs only need
fixing in one place.

Also home of the ``\\n``-only line model (``split_lines``): any code
that pairs source text with an EXTERNAL line number — semgrep,
CodeQL SARIF, tree-sitter rows, Python ``ast.lineno``, DWARF, gcc
diagnostics, git hunks, editors — must split on ``\\n`` only, never
``str.splitlines()``.  See ``split_lines`` for the full contract.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "number_lines",
    "read_context",
    "read_lines",
    "slice_lines",
    "slice_text",
    "split_lines",
]

#: Every terminator ``str.splitlines()`` recognises BEYOND ``\n`` /
#: ``\r\n``.  ``split_lines`` deliberately does NOT split on these
#: (bare ``\r`` included — see the docstring's producer-family
#: table); a closure test derives the set from ``str.splitlines``
#: itself so a future Python widening it fails loudly.
_SPLITLINES_ONLY_TERMINATORS: tuple[str, ...] = (
    "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029",
)
#: Excluded single-char breakers = the exotics plus bare ``\r``.
_NON_NL_BREAKERS: tuple[str, ...] = ("\r", *_SPLITLINES_ONLY_TERMINATORS)


def split_lines(text: str) -> list[str]:
    r"""Split source text into lines on ``\n`` ONLY.

    Every external line-number producer RAPTOR consumes — semgrep,
    CodeQL SARIF, tree-sitter rows, DWARF, gcc diagnostics, git
    hunks, editors — counts ``\n`` as the only line terminator.
    ``str.splitlines()`` additionally breaks on ``\r``, ``\v``
    (\x0b), ``\f`` (\x0c), ``\x1c``, ``\x1d``, ``\x1e``,
    ``\x85`` (NEL), ``\u2028``, and ``\u2029`` — bytes that are
    legal inside comments and string literals everywhere, and (for
    ``\f``) legal code WHITESPACE in C and Python.  One such
    attacker-plantable byte therefore shifts every subsequent
    ``splitlines()`` index off the tool-reported line numbers:
    guards are harvested from planted lines, LLM analysts are shown
    substitute code, suppression comments are forged.  Never index a
    ``splitlines()`` list with an external line number; split with
    this helper instead.

    The ``\r`` model, per producer family (bare ``\r`` is a
    plantable byte too, so it must NOT open a line):

    * ``\r\n`` — one break everywhere.  Splitting on ``\n`` leaves
      the ``\r`` at the end of the previous element; ONE trailing
      ``\r`` per line is trimmed so byte-decoded input
      (``open('rb')`` + ``decode``, or a ``newline=""`` text read)
      yields the same line CONTENT as universal-newline ``read_text``
      while keeping the ``\n`` count.
    * bare ``\r`` — NOT a break.  semgrep, tree-sitter, and the
      raw-byte scanner family keep it inside the line (verified
      empirically), so did this helper turn it into a break, one
      0x0D would reopen the exact desync this helper exists to
      close.  Note that a universal-newline ``read_text`` upstream
      translates bare ``\r`` to ``\n`` BEFORE this helper runs —
      callers pairing with raw-byte scanners must read with
      ``newline=""`` or decode bytes themselves (see
      ``read_text_capped``'s ``newline`` parameter).
    * CPython ``ast`` is the one \r-BREAKING producer.  ast-paired
      callers must normalise their parse input first so the parsed
      text and the split text share one model (``fail_open_lang``
      does), or guarantee universal-newline reads.

    A single trailing empty element (text ending in ``\n``) is
    dropped, matching editor line counts for well-formed text.
    """
    lines = text.split("\n")
    if "\r" in text:
        lines = [
            line[:-1] if line.endswith("\r") else line
            for line in lines
        ]
    if lines and lines[-1] == "":
        lines.pop()
    return lines


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
    ranges.  Splits with ``split_lines`` (``\\n`` model): line
    ranges arrive from external producers that count ``\\n``, so a
    ``splitlines()`` view would hand back attacker-shifted lines.
    """
    result = slice_lines(split_lines(text), start_line, end_line)
    return "\n".join(result) if result else ""


def read_lines(
    path: Path, start_line: int, end_line: int,
) -> str:
    """Read a line range from a file on disk.

    Returns ``""`` if the file is unreadable or the range is empty.
    Uses ``errors="replace"`` so non-UTF-8 bytes don't raise.
    Reads with universal newlines: fine for internal-convention line
    ranges, but a caller pairing with raw-byte scanner line numbers
    must read with ``newline=""`` itself (see ``split_lines``'s
    producer-family table) — universal translation turns a plantable
    bare ``\r`` into a break before any splitter runs.
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
