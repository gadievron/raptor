"""Historical binary-context dependencies, never verification or cold reuse.

A persisted record cannot recreate the live module/view ownership used during
review. Consumers retain these assessments in the journal and require a new
review rather than projecting them into existence-only coverage.
"""
from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json
from typing import Any

from core.json import dumps_canonical
from .binary_review_scope import BinaryKnowledgeOrigin
from .continuation_context import context_spec
from .review_context_inputs import MAX_SNAPSHOT_BYTES

_ROLE = "binary-review-context-inputs"
_PREFIX = "bin:ctx1:"


def capture_binary_context_inputs(ctx: dict, origin: BinaryKnowledgeOrigin, deliveries: object) -> dict | None:
    """Describe exact complete fitted sections under an original binary origin.

    The caller supplies invocation-owned delivery receipts. This captures data;
    it does not authenticate receipts or reconstruct a publication capability.
    Missing or truncated sections cannot produce a complete input record.
    """
    if not isinstance(origin, BinaryKnowledgeOrigin) or not isinstance(deliveries, list) or not deliveries:
        return None
    contexts = []
    for row in deliveries:
        if not isinstance(row, dict) or row.get("delivered") is not True or row.get("reason") != "complete_prompt_section":
            return None
        kind, version = row.get("kind"), row.get("version")
        if not isinstance(kind, str) or not isinstance(version, str):
            return None
        spec = context_spec(ctx, kind=kind, version=version)
        if spec is None or row != {**spec, "delivered": True, "reason": "complete_prompt_section"}:
            return None
        if spec not in contexts:
            contexts.append(spec)
    record = {"version": 1, "role": _ROLE, "origin": asdict(origin),
              "contexts": sorted(contexts, key=lambda item: item["context_id"])}
    encoded = dumps_canonical(record).encode()
    return record if len(encoded) <= MAX_SNAPSHOT_BYTES else None


def binary_context_record_digest(record: object) -> str | None:
    """Digest bounded historical data only; even a matching digest grants no reuse."""
    if (not isinstance(record, dict) or set(record) != {"version", "role", "origin", "contexts"}
            or type(record.get("version")) is not int or record["version"] != 1
            or record.get("role") != _ROLE or not isinstance(record.get("origin"), dict)
            or not isinstance(record.get("contexts"), list) or not record["contexts"]):
        return None
    try:
        # Historical records must already be JSON data; canonical JSON's
        # default=str must not silently stringify borrowed runtime objects.
        json.dumps(record, allow_nan=False)
        encoded = dumps_canonical(record).encode()
    except (ValueError, TypeError, UnicodeEncodeError, RecursionError, OverflowError):
        return None
    return sha256(encoded).hexdigest() if len(encoded) <= MAX_SNAPSHOT_BYTES else None


def binary_context_anchor(origin: BinaryKnowledgeOrigin, record: object) -> str | None:
    """Keep the context marker even in projections which discard history."""
    if not isinstance(origin, BinaryKnowledgeOrigin) or not isinstance(record, dict):
        return None
    digest = binary_context_record_digest(record)
    if digest is None or dumps_canonical(record.get("origin")) != dumps_canonical(asdict(origin)):
        return None
    identity = origin.binary_identity
    return (f"{_PREFIX}{digest}:{identity.module_sha256}:{identity.address:x}:{identity.size:x}"
            if digest is not None else None)


def binary_context_bound(source_hash: object, history: object) -> bool:
    """Recognise even incomplete records so loss cannot fall back to plain credit."""
    return (isinstance(source_hash, str) and source_hash.startswith("bin:ctx")
            or isinstance(history, dict) and "binary_inputs" in history)


def merge_binary_context_inputs(*snapshots: object) -> dict | None:
    """Retain bounded contributors; missing data stays an explicit unknown.

    Contributor records remain historical data. Neither union nor a complete
    envelope authenticates a delivery or makes the context reusable.
    """
    records = {}
    complete, present = True, False
    for snapshot in snapshots:
        if snapshot is None:
            continue
        present = True
        if (isinstance(snapshot, dict) and snapshot.get("role") == _ROLE
                and set(snapshot) == {"version", "role", "inputs", "complete"}
                and type(snapshot.get("version")) is int and snapshot["version"] == 1
                and isinstance(snapshot.get("inputs"), list)):
            values = snapshot["inputs"]
            complete = complete and snapshot.get("complete") is True
        else:
            values = [snapshot]
        for value in values:
            digest = binary_context_record_digest(value)
            if digest is None:
                complete = False
                continue
            copied = json.loads(dumps_canonical(value))
            records[digest] = copied
    if not present:
        return None
    if complete and len(records) == 1:
        return next(iter(records.values()))
    result: dict[str, Any] = {"version": 1, "role": _ROLE, "inputs": [], "complete": complete}
    for digest in sorted(records):
        result["inputs"].append(records[digest])
        if len(dumps_canonical({**result, "complete": False}).encode()) > MAX_SNAPSHOT_BYTES:
            result["inputs"].pop()
            result["complete"] = False
    return result
