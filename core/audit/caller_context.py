"""Bounded caller entry context, separate from the local call-site window."""

from __future__ import annotations

from pathlib import Path


CALLER_ENTRY_LINES = 12
CALLER_ENTRY_CHARS = 1200
_DOC_LOOKBACK_LINES = 40


def _doc_summary(lines: list[str]) -> tuple[int, str] | None:
    """First substantive line of an adjacent block comment, if any."""
    end = len(lines) - 1
    while end >= 0 and not lines[end].strip():
        end -= 1
    if end < 0 or not lines[end].rstrip().endswith("*/"):
        return None
    for start in range(end, -1, -1):
        if not lines[start].lstrip().startswith("/*"):
            continue
        for i in range(start, end + 1):
            text = lines[i].strip().removeprefix("/**").removeprefix("/*")
            text = text.removesuffix("*/").lstrip("* ").strip()
            if text:
                return i, lines[i][:256]
        return None
    return None


def enrich_caller_entries(callers: list[dict], target_path: Path, inventory: dict | None) -> None:
    """Attach signatures, setup, and an adjacent doc-comment summary.

    Only known caller boundaries qualify: an arbitrary first-N-lines
    scan could attribute the next function's setup to a short caller.
    No code outside the caller's recorded span is included.
    """
    if not inventory:
        return
    from .context import _read_target_line_window, _safe_path

    wanted = {(c.get("file"), c.get("name"), c.get("line_start")) for c in callers}
    spans = {}
    wanted_files = {key[0] for key in wanted}
    for file in inventory.get("files", []):
        path = file.get("path")
        if path not in wanted_files:
            continue
        for item in file.get("items", []):
            key = (path, item.get("name"), item.get("line_start"))
            if key in wanted:
                spans[key] = item.get("line_end")
    for caller in callers:
        key = (caller.get("file"), caller.get("name"), caller.get("line_start"))
        first, last = key[2], spans.get(key)
        if not isinstance(first, int) or not isinstance(last, int) or not 0 < first <= last:
            continue
        path = _safe_path(target_path, key[0])
        if path is None:
            continue
        window_start = max(0, first - 1 - _DOC_LOOKBACK_LINES)
        lines = _read_target_line_window(path, window_start, min(last, first - 1 + CALLER_ENTRY_LINES))
        if not lines:
            continue
        entry_start = first - 1 - window_start
        summary = _doc_summary(lines[:entry_start])
        entry = lines[entry_start:]
        excerpt = "\n".join(f"{first + i:4d}  {line}" for i, line in enumerate(entry))
        if summary is not None:
            i, text = summary
            excerpt = f"{window_start + i + 1:4d}  {text}\n" + excerpt
        if len(excerpt) > CALLER_ENTRY_CHARS:
            excerpt = excerpt[:CALLER_ENTRY_CHARS - len("\n[truncated]")] + "\n[truncated]"
        caller["caller_entry"] = excerpt
