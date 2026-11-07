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
    from collections.abc import Iterable, Iterator
    from pathlib import Path

__all__ = [
    "iter_splitlines",
    "join_lf_slice",
    "join_lines_prefix",
    "number_lines",
    "read_context",
    "read_lines",
    "slice_lines",
    "slice_text",
    "split_lines",
    "splitlines_prefix",
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

# Python's display-line model, separate from source-coordinate LF splitting.
_DISPLAY_LINE_BREAKERS = ("\n", *_NON_NL_BREAKERS)
_SPLITLINES_CHUNK_CHARS = 4096


def iter_splitlines(text: str) -> Iterator[str]:
    """Yield Python display lines without building the entire line list.

    Match ``str.splitlines()`` including CRLF, Unicode separators and the
    omitted trailing empty line. Temporary work is chunked, except for a
    single long line. Source coordinates must use ``split_lines``.
    String adapters retain their own splitlines operation.
    """
    if type(text) is not str:
        yield from text.splitlines()
        return
    start = scan = 0
    while scan < len(text):
        stop = min(scan + _SPLITLINES_CHUNK_CHARS, len(text))
        end = max(text.rfind(c, scan, stop) for c in _DISPLAY_LINE_BREAKERS) + 1
        if not end:
            scan = stop
            continue
        # A CR at the chunk edge may belong to the next character's CRLF.
        if text[end - 1] == "\r" and end < len(text) and text[end] == "\n":
            end += 1
        # Split complete display lines in C. Retain no partial-line copies;
        # an unusually long line can span several search chunks.
        yield from text[start:end].splitlines()
        start = scan = end
    if start < len(text):
        yield text[start:]


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
    lines = text.split("\n")  # line-model: this IS the \n-only chokepoint (one trailing \r trimmed below)
    if "\r" in text:
        lines = [
            line.removesuffix("\r")
            for line in lines
        ]
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def splitlines_prefix(text: str, limit: int) -> list[str]:
    """Return ``text.splitlines()[:limit]`` with bounded prefix splitting.

    Retain Python's full display-line model, including bare CR and Unicode
    separators. Source coordinates use ``split_lines`` instead. For large
    native strings, a small LF-terminated prefix contains at least as many
    display lines as LF breaks, so its first ``limit`` lines are identical.
    Other inputs and layouts retain the original split/slice operations.
    """
    if (type(text) is str and type(limit) is int
            and len(text) >= 16 * 1024 and 0 < limit <= 128):
        end = 0
        for _ in range(limit):
            found = text.find("\n", end, 16 * 1024)
            if found < 0:
                break
            end = found + 1
        else:
            # Include the last LF: dropping it loses an empty final
            # prefix line when consecutive separators occur at the cut.
            return text[:end].splitlines()[:limit]
    return text.splitlines()[:limit]


def join_lines_prefix(lines: Iterable[str], max_chars: int) -> str:
    """Return a nonnegative character prefix of LF-joined lines.

    Stop consuming lines once the prefix is complete. Unused lines are not
    validated or materialized; callers may request cap + 1 to detect overflow.
    """
    if max_chars < 0:
        raise ValueError("max_chars must be nonnegative")
    if max_chars == 0:
        return ""
    parts: list[str] = []
    remaining = max_chars
    for line in lines:
        if parts:
            parts.append("\n")
            remaining -= 1
            if remaining == 0:
                break
        prefix = line[:remaining]
        parts.append(prefix)
        remaining -= len(prefix)
        if remaining == 0:
            break
    return "".join(parts)


def join_lf_slice(text: str, start: int, end: int) -> str:
    """Equivalent to ``"\\n".join(text.split("\\n")[start:end])``.

    Bounds are zero-based and half-open. Preserve CR characters and the
    trailing empty split element: this raw LF model differs from
    ``split_lines``. Negative bounds, subclasses, and unusual index types
    retain the original split/slice operations.
    """
    if (type(text) is not str or type(start) is not int or type(end) is not int
            or start < 0 or end < 0 or len(text) < 16 * 1024):
        return "\n".join(text.split("\n")[start:end])  # line-model: raw LF slicing preserves CR and the trailing empty element
    if start >= end:
        return ""
    if end <= 128:
        # Bound Python-level searches to small windows near the start.
        lower = 0
        for _ in range(start):
            found = text.find("\n", lower)
            if found < 0:
                return ""
            lower = found + 1
        upper = lower
        for _ in range(end - start):
            found = text.find("\n", upper)
            if found < 0:
                return text[lower:]
            upper = found + 1
        return text[lower:upper - 1]
    # Split only the prefix through the requested end. Discard the
    # unsplit tail before joining, and clamp huge Python slice bounds
    # before passing them to split's Py_ssize_t maxsplit argument.
    parts = text.split("\n", min(end, len(text)))  # line-model: same raw LF slice contract; retain CR
    if len(parts) > end:
        parts.pop()
    parts = parts[start:end]
    return "\n".join(parts)


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
    if (type(text) is str and type(start_line) is int and type(end_line) is int
            and len(text) >= 16 * 1024 and start_line > 0 and end_line >= start_line):
        selected = join_lf_slice(text, start_line - 1, end_line)
        if not selected:
            return ""
        if "\r" in selected:
            result = [line.removesuffix("\r") for line in selected.split("\n")]  # line-model: exactly one trailing CR is trimmed here
            # Only the file's final empty normalized element is dropped.
            # An empty line inside the requested window must remain.
            if result[-1] == "" and end_line > text.count("\n"):
                result.pop()
            return "\n".join(result)
        if selected.endswith("\n") and end_line > text.count("\n"):
            return selected[:-1]
        return selected
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
