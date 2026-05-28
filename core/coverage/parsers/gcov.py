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
from typing import Dict, Set

_NEVER = ("-", "#####", "=====")
_SOURCE_RE = re.compile(r"Source:(.*)")


def parse_gcov(path) -> Dict[str, Set[int]]:
    """Parse a ``.gcov`` file, or a directory of them."""
    p = Path(path)
    files = sorted(p.glob("*.gcov")) if p.is_dir() else [p]
    out: Dict[str, Set[int]] = {}
    for gcov_file in files:
        _parse_one_gcov(gcov_file, out)
    return out


def _parse_one_gcov(gcov_file: Path, out: Dict[str, Set[int]]) -> None:
    try:
        text = gcov_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    src = None
    lines: Set[int] = set()
    for raw in text.splitlines():
        parts = raw.split(":", 2)              # count : lineno : source
        if len(parts) < 2:
            continue
        count_s, lineno_s = parts[0].strip(), parts[1].strip()
        if lineno_s == "0":                    # metadata line
            if len(parts) > 2:
                m = _SOURCE_RE.match(parts[2].strip())
                if m:
                    src = m.group(1).strip()
            continue
        try:
            lineno = int(lineno_s)
        except ValueError:
            continue
        if not count_s or count_s in _NEVER:
            continue
        # Executed: a plain count > 0, OR a human-readable count (`1.2k`, gcov
        # `-H`) which gcov only emits for non-zero counts. `-`/`#####`/`=====`
        # (handled above) are the only "not executed" markers.
        try:
            if int(count_s) <= 0:
                continue
        except ValueError:
            pass                               # human-readable non-zero count
        lines.add(lineno)
    if lines:
        # Prefer the Source: header; fall back to the .gcov stem
        # (Path.stem strips the .gcov suffix: foo.c.gcov -> foo.c).
        out.setdefault(src or gcov_file.stem, set()).update(lines)


def parse_lcov(path) -> Dict[str, Set[int]]:
    """Parse an lcov ``.info`` file (``SF:`` / ``DA:`` records)."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    out: Dict[str, Set[int]] = {}
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
