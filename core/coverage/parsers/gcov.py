"""Parse gcov / lcov coverage into executed source lines.

- raw ``.gcov`` files: each code line is ``<count>:<lineno>:<source>``. Executed
  iff ``count`` is a number > 0 (``-`` = non-code, ``#####`` / ``=====`` = never
  executed). The ``Source:<path>`` header (lineno 0) names the source file.
- lcov ``.info``: ``SF:<path>`` opens a file section; ``DA:<line>,<count>`` is a
  line with an execution count; count > 0 = executed; ``end_of_record`` closes it.

Both return ``{source_path: set(executed_line_numbers)}``. Tolerant — malformed
lines are skipped, never raised.
"""

from __future__ import annotations

import re
from pathlib import Path

from core.source.streams import preserving_stream_error

_NEVER = ("-", "#####", "=====")
_SOURCE_RE = re.compile(r"Source:(.*)")
_COUNT_RE = re.compile(r"(?P<number>[0-9]+(?:\.[0-9]+)?)(?P<unit>[kMGTPEZY])?\*?")
_SGR_RE = re.compile(r"\x1b\[[0-9;]*m")

# Coverage artifacts scale with the instrumented tree — same budget
# class as the sibling coverage_py parser (_MAX_REPORT_BYTES there).
# These files arrive via the artifact-import path (another principal's
# write grant), so the read is size-gated instead of unbounded.
_MAX_REPORT_BYTES = 256 * 1024 * 1024


def _read_report_text(path: Path) -> str | None:
    """Bounded read for a coverage artifact; None when unreadable or
    over the byte budget (skipped like any malformed input)."""
    try:
        with preserving_stream_error(path.open("rb")) as fh:
            raw = fh.read(_MAX_REPORT_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _MAX_REPORT_BYTES:
        return None
    return raw.decode("utf-8", errors="replace")


def parse_gcov(path) -> dict[str, set[int]]:
    """Parse a ``.gcov`` file, or a directory of them."""
    p = Path(path)
    files = sorted(p.glob("*.gcov")) if p.is_dir() else [p]
    out: dict[str, set[int]] = {}
    for gcov_file in files:
        _parse_one_gcov(gcov_file, out)
    return out


def _parse_one_gcov(gcov_file: Path, out: dict[str, set[int]]) -> None:
    text = _read_report_text(gcov_file)
    if text is None:
        return
    # Prefer the Source: header; fall back to the .gcov stem
    # (Path.stem strips the .gcov suffix: foo.c.gcov -> foo.c).
    src: str | None = None
    lines: set[int] = set()

    def _flush() -> None:
        if lines:
            out.setdefault(src or gcov_file.stem, set()).update(lines)

    for raw in text.splitlines():
        parts = raw.split(":", 2)              # count : lineno : source
        if len(parts) < 2:
            continue
        count_s, lineno_s = parts[0].strip(), parts[1].strip()
        if lineno_s == "0":                    # metadata line
            if len(parts) > 2:
                m = _SOURCE_RE.match(parts[2].strip())
                if m:
                    # A gcov file can carry MULTIPLE Source: sections
                    # (headers included with -a/-l runs). Flush the
                    # accumulated lines to the CURRENT source before
                    # switching — without this every section's lines
                    # were attributed to the LAST file (overstated
                    # runtime coverage on it, first file's coverage
                    # vanished).
                    _flush()
                    lines = set()
                    src = m.group(1).strip()
            continue
        try:
            lineno = int(lineno_s)
        except ValueError:
            continue
        if not count_s or count_s in _NEVER:
            continue
        # GCC emits integers, optional partial-execution '*', and -H
        # counts with k/M/... suffixes (integer or decimal mantissas).
        # Colour options wrap the count in SGR escapes, including zero.
        token = _SGR_RE.sub("", count_s).strip()
        count = _COUNT_RE.fullmatch(token)
        if (count is None
                or ("." in count["number"] and not count["unit"])
                or not any(char in "123456789" for char in count["number"])):
            continue
        lines.add(lineno)
    _flush()


def parse_lcov(path) -> dict[str, set[int]]:
    """Parse an lcov ``.info`` file (``SF:`` / ``DA:`` records)."""
    text = _read_report_text(Path(path))
    if text is None:
        return {}
    out: dict[str, set[int]] = {}
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("SF:"):
            cur = line[3:].strip() or None
        elif line == "end_of_record":
            cur = None
        elif line.startswith("DA:") and cur:
            bits = line[3:].split(",")
            if len(bits) >= 2:
                try:
                    lineno, count = int(bits[0]), int(bits[1])
                except ValueError:
                    continue
                if count > 0:
                    out.setdefault(cur, set()).add(lineno)
    return out
