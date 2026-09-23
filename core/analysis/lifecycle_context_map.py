"""Context-map integration for lifecycle-precondition analysis.

Adds a ``state_fields`` section to context-map.json carrying
lifecycle-sensitive fields, their write-site preconditions, and read
sites.

WIRING STATUS: nothing in the pipeline currently WRITES this section
(``save_state_fields``/``discover_state_fields`` have no production
call sites), so ``load_state_fields`` returns ``[]`` on every run and
the one wired reader — the /audit orchestrator's
``check_lifecycle_at_function`` — is a no-op. /understand --hunt and
/validate Stage B do not read it. A repository test pins this status
in both directions: wiring a producer must update these docstrings.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from core.artifacts.context_map_budget import (
    CONTEXT_MAP_CONSUMER_MAX_BYTES,
    save_context_map,
)
from core.json import load_json

from .lifecycle_model import StateField

logger = logging.getLogger(__name__)

# context-map.json is RAPTOR-written run output (multi-MiB on big
# targets). Read cap shared with the producer-side budget.
_MAX_CONTEXT_MAP_BYTES = CONTEXT_MAP_CONSUMER_MAX_BYTES


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

    save_context_map(cm_path, data)
    return cm_path


def merge_state_fields(
    existing: list[StateField],
    new_fields: list[StateField],
) -> list[StateField]:
    """Merge new state fields with existing, deduplicating by
    name+struct_type. Pure: callers' ``existing`` fields (and their
    site lists) are never mutated — merged entries are fresh
    dataclass copies."""
    from dataclasses import replace
    by_key = {(f.name, f.struct_type): f for f in existing}
    for f in new_fields:
        key = (f.name, f.struct_type)
        if key in by_key:
            prev = by_key[key]
            ws = list(prev.write_sites)
            ws_set = {(w.line, w.file) for w in ws}
            ws.extend(w for w in f.write_sites
                      if (w.line, w.file) not in ws_set)
            rs = list(prev.read_sites)
            rs_set = {(r.line, r.file) for r in rs}
            rs.extend(r for r in f.read_sites
                      if (r.line, r.file) not in rs_set)
            by_key[key] = replace(prev, write_sites=ws, read_sites=rs)
        else:
            by_key[key] = f
    return list(by_key.values())
