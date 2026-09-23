"""Schema helpers for RAPTOR's internal /understand graph store."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = 3

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
    "hypothesis",
    "tool_verdict",
    "scan_finding",
    "codeql_result",
    "annotation",
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
    "IMPORTS",
    "AFFECTS",
    "TESTED_BY",
    "SUPPRESSED_BY",
    "ANNOTATED",
    "VALIDATES",
}


def _like_escape(value: str) -> str:
    r"""Escape LIKE wildcards using backslash as escape char.

    THE one home — queries (and any future ingest LIKE) import it
    here instead of keeping byte-identical per-module copies.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def utc_now_iso() -> str:
    """THE created_at mint. snapshots order lexicographically on this
    column, and 'T' sorts above ' ' — a second space-separated
    datetime('now') mint made same-day snapshots from one producer
    always rank older than everyone else's regardless of time."""
    return datetime.now(timezone.utc).isoformat()


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


def function_ref(file_path: Any, name: Any) -> str:
    """THE ``<file>::<name>`` reference for function-node keys.

    Every producer that mints a function node key and every consumer
    that looks one up must build the ref here — hand-rolled
    ``f"{path}::{name}"`` spellings are exactly how cross-producer
    joins go silently inert (seam registered in
    .github/tests/test_join_seam_registry.py). Deliberately does NOT
    normalise path spellings: producers write checklist-relative
    paths and same-spelling consumers join on them; cross-producer
    path normalisation is the pending constructor-unification work.
    """
    return f"{file_path}::{name}"


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


def content_hash(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("rule_id") or finding.get("query_id") or ""),
        str(finding.get("message") or finding.get("description") or ""),
        str(finding.get("snippet") or ""),
    ]
    return short_hash("::".join(parts), length=12)
