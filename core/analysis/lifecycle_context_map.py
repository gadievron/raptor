"""Context-map integration for lifecycle-precondition analysis.

Adds a ``state_fields`` section to context-map.json carrying
lifecycle-sensitive fields, their write-site preconditions, and
read sites.  Consumed by /audit orchestrator, /understand --hunt,
and /validate Stage B.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from .lifecycle_model import StateField

logger = logging.getLogger(__name__)


def load_state_fields(out_dir: Path) -> List[StateField]:
    """Load state fields from context-map.json's state_fields section."""
    cm_path = out_dir / "context-map.json"
    if not cm_path.exists():
        return []

    try:
        data = json.loads(cm_path.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    raw_fields = data.get("state_fields", [])
    fields: List[StateField] = []
    for raw in raw_fields:
        try:
            fields.append(StateField.from_dict(raw))
        except (KeyError, TypeError, ValueError) as exc:
            logger.debug("skipping malformed state_field: %s", exc)
    return fields


def save_state_fields(
    out_dir: Path,
    fields: List[StateField],
) -> Path:
    """Write state fields into context-map.json's state_fields section.

    Merges with existing context-map content if present.
    Returns the path to the written file.
    """
    cm_path = out_dir / "context-map.json"

    data: Dict[str, Any] = {}
    if cm_path.exists():
        try:
            data = json.loads(cm_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    data["state_fields"] = [f.to_dict() for f in fields]

    cm_path.write_text(json.dumps(data, indent=2) + "\n")
    return cm_path


def merge_state_fields(
    existing: List[StateField],
    new_fields: List[StateField],
) -> List[StateField]:
    """Merge new state fields with existing, deduplicating by name+struct_type."""
    seen = {(f.name, f.struct_type) for f in existing}
    merged = list(existing)
    for f in new_fields:
        key = (f.name, f.struct_type)
        if key not in seen:
            seen.add(key)
            merged.append(f)
    return merged
