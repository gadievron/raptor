"""Context-map integration for lifecycle-precondition analysis.

Adds a ``state_fields`` section to context-map.json carrying
lifecycle-sensitive fields, their write-site preconditions, and
read sites.  Consumed by /audit orchestrator, /understand --hunt,
and /validate Stage B.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from core.json import load_json

from .lifecycle_model import StateField

logger = logging.getLogger(__name__)

# context-map.json is RAPTOR-written run output (multi-MiB on big
# targets) — the audit-artifact budget class.
_MAX_CONTEXT_MAP_BYTES = 64 * 1024 * 1024


def load_state_fields(out_dir: Path) -> list[StateField]:
    """Load state fields from context-map.json's state_fields section."""
    cm_path = out_dir / "context-map.json"
    if not cm_path.exists():
        return []

    data = load_json(cm_path, max_bytes=_MAX_CONTEXT_MAP_BYTES)
    if not isinstance(data, dict):
        return []

    raw_fields = data.get("state_fields", [])
    fields: list[StateField] = []
    for raw in raw_fields:
        try:
            fields.append(StateField.from_dict(raw))
        except (KeyError, TypeError, ValueError) as exc:
            logger.debug("skipping malformed state_field: %s", exc)
    return fields


def save_state_fields(
    out_dir: Path,
    fields: list[StateField],
) -> Path:
    """Write state fields into context-map.json's state_fields section.

    Merges with existing context-map content if present.
    Returns the path to the written file.
    """
    cm_path = out_dir / "context-map.json"

    data: dict[str, Any] = {}
    if cm_path.exists():
        loaded = load_json(cm_path, max_bytes=_MAX_CONTEXT_MAP_BYTES)
        if isinstance(loaded, dict):
            data = loaded

    data["state_fields"] = [f.to_dict() for f in fields]

    fd, tmp_path = tempfile.mkstemp(dir=str(cm_path.parent), suffix=".tmp")
    try:
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        import os
        os.replace(tmp_path, str(cm_path))
    except BaseException:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return cm_path


def merge_state_fields(
    existing: list[StateField],
    new_fields: list[StateField],
) -> list[StateField]:
    """Merge new state fields with existing, deduplicating by name+struct_type."""
    by_key = {(f.name, f.struct_type): f for f in existing}
    for f in new_fields:
        key = (f.name, f.struct_type)
        if key in by_key:
            prev = by_key[key]
            ws_set = {(w.line, w.file) for w in prev.write_sites}
            for w in f.write_sites:
                if (w.line, w.file) not in ws_set:
                    prev.write_sites.append(w)
            rs_set = {(r.line, r.file) for r in prev.read_sites}
            for r in f.read_sites:
                if (r.line, r.file) not in rs_set:
                    prev.read_sites.append(r)
        else:
            by_key[key] = f
    return list(by_key.values())
