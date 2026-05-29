"""Parse coverage.py output into executed source lines.

Reads the ``coverage json`` report (``{"files": {path: {"executed_lines":
[...]}}}``) — the stable, documented interface. The raw ``.coverage`` SQLite DB
is intentionally NOT parsed (schema-coupled); run ``coverage json`` first.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Set


def parse_coverage_py(path) -> Dict[str, Set[int]]:
    """Return ``{source_path: set(executed_line_numbers)}`` from a coverage.json
    report (or a directory containing one). Tolerant: bad/missing pieces are
    skipped, never raised."""
    p = Path(path)
    if p.is_dir():
        cand = p / "coverage.json"
        if cand.exists():
            p = cand
    try:
        data = json.loads(Path(p).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        return {}
    out: Dict[str, Set[int]] = {}
    for src, info in files.items():
        if not isinstance(src, str) or not isinstance(info, dict):
            continue
        executed = info.get("executed_lines")
        if not isinstance(executed, list):
            continue
        nums = {n for n in executed if isinstance(n, int) and not isinstance(n, bool)}
        if nums:
            out[src] = nums
    return out
