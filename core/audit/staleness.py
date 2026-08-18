"""Stale annotation detection for the orchestrator.

Detects functions whose source has changed since their annotation was
written (hash mismatch). These are candidates for re-review.

Extracts the reusable loop from the CLI stale commands so both the
skill-driven /audit and the Python orchestrator can find stale items.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class StaleItem:
    file: str
    function: str
    old_hash: str
    new_hash: str
    reason: str
    line_start: int = 0
    line_end: int = 0


def find_stale_annotations(
    annotations_dir: Path,
    target_path: Path,
) -> list[StaleItem]:
    """Find annotations whose source has changed or been deleted.

    Returns a list of StaleItem for each annotation where:
    - The source file was deleted
    - The function hash doesn't match the annotation's stored hash

    Annotations without hash metadata are skipped (they can't be
    checked for staleness).
    """
    try:
        from core.annotations.storage import (
            compute_function_hash,
            iter_all_annotations,
        )
    except ImportError:
        logger.debug("annotations module not available")
        return []

    stale = []
    for ann in iter_all_annotations(annotations_dir):
        old_hash = ann.metadata.get("hash")
        if not old_hash:
            continue

        full_path = (target_path / ann.file).resolve()
        # Guard against path traversal in annotation file field
        target_resolved = str(target_path.resolve()) + os.sep
        if not str(full_path).startswith(target_resolved):
            logger.warning(
                "skipping annotation with path traversal: %s", ann.file,
            )
            continue
        if not full_path.exists():
            stale.append(StaleItem(
                file=ann.file,
                function=ann.function,
                old_hash=old_hash,
                new_hash="",
                reason="deleted",
            ))
            continue

        try:
            line_start = int(ann.metadata.get("line_start", "0") or "0")
            line_end = int(ann.metadata.get("line_end", "0") or "0")
        except (ValueError, TypeError):
            continue
        if not (line_start and line_end):
            continue

        new_hash = compute_function_hash(full_path, line_start, line_end)
        if new_hash and new_hash != old_hash:
            stale.append(StaleItem(
                file=ann.file,
                function=ann.function,
                old_hash=old_hash,
                new_hash=new_hash,
                reason="modified",
                line_start=line_start,
                line_end=line_end,
            ))

    return stale


def stale_as_gaps(
    stale_items: list[StaleItem],
    existing_gaps: list[dict] | None = None,
) -> list[dict]:
    """Convert stale annotations into gap-format dicts for the orchestrator.

    Merges stale items with existing gaps, marking stale items with
    is_stale=True and priority=0 (highest priority for re-review).
    Avoids duplicates — if a stale function is already in the gap list,
    just sets is_stale=True on the existing entry.
    """
    by_key: dict = {}
    result = []

    if existing_gaps:
        for gap in existing_gaps:
            key = f"{gap['file']}:{gap['name']}"
            # First occurrence wins for collision marking, matching the
            # previous first-match scan.
            by_key.setdefault(key, gap)
            result.append(gap)

    for item in stale_items:
        if item.reason == "deleted":
            continue
        key = f"{item.file}:{item.function}"
        existing = by_key.get(key)
        if existing is not None:
            existing["is_stale"] = True
            existing["priority"] = 0
        else:
            gap = {
                "file": item.file,
                "name": item.function,
                "line_start": item.line_start,
                "line_end": item.line_end,
                "priority": 0,
                "strategies": [],
                "is_stale": True,
                "sloc": max(0, item.line_end - item.line_start + 1) if item.line_end else 0,
            }
            result.append(gap)
            by_key[key] = gap

    return result
