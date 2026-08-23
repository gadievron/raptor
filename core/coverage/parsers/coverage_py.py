"""Parse coverage.py output into executed source lines.

Reads the ``coverage json`` report (``{"files": {path: {"executed_lines":
[...]}}}``) — the stable, documented interface. The raw ``.coverage`` SQLite DB
is intentionally NOT parsed (schema-coupled); run ``coverage json`` first.
"""

from __future__ import annotations

from pathlib import Path

from core.json import load_json

# coverage.json reports scale with the instrumented tree — the
# coverage-store budget class.
_MAX_REPORT_BYTES = 256 * 1024 * 1024


def parse_coverage_py(path) -> dict[str, set[int]]:
    """Return ``{source_path: set(executed_line_numbers)}`` from a coverage.json
    report (or a directory containing one). Tolerant: bad/missing pieces are
    skipped, never raised."""
    p = Path(path)
    if p.is_dir():
        cand = p / "coverage.json"
        if cand.exists():
            p = cand
    data = load_json(p, max_bytes=_MAX_REPORT_BYTES)
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        return {}
    out: dict[str, set[int]] = {}
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
