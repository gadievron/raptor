"""Schema helpers for RAPTOR's internal /understand graph store."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SCHEMA_VERSION = 1

NODE_KINDS = {
    "file",
    "function",
    "entry_point",
    "source",
    "trust_boundary",
    "sink",
    "unchecked_flow",
    "flow_trace",
    "trace_step",
    "variant",
    "finding",
    "threat",
    "dependency",
    "verified_outcome",
}

EDGE_KINDS = {
    "CONTAINS",
    "CALLS",
    "REACHES",
    "TAINTS",
    "CROSSES_BOUNDARY",
    "HAS_SOURCE",
    "HAS_SINK",
    "CONFIRMED_BY",
    "BLOCKED_BY",
    "DERIVED_FROM",
    "IMPORTS_DEP",
    "AFFECTS",
}


def json_dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"))


def json_loads(value: str | None) -> Any:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


def short_hash(value: Any, *, length: int = 16) -> str:
    if not isinstance(value, str):
        value = json_dumps(value)
    return hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()[:length]


def _clean_part(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text or "unknown"


def stable_key(kind: str, *parts: Any) -> str:
    body = "::".join(_clean_part(p) for p in parts if p is not None)
    if not body:
        body = "unknown"
    return f"{kind}://{body}"


def stable_node_id(kind: str, *parts: Any) -> str:
    return f"node:{kind}:{short_hash(stable_key(kind, *parts))}"


def stable_edge_id(kind: str, src_id: str, dst_id: str, *parts: Any) -> str:
    extra = "::".join(_clean_part(p) for p in parts if p is not None)
    return f"edge:{kind}:{short_hash(f'{src_id}->{dst_id}:{extra}')}"


def snapshot_id(target_path: str, checklist_hash: str, producer_run: str) -> str:
    return f"snap:{short_hash({'target': target_path, 'checklist': checklist_hash, 'run': producer_run})}"
