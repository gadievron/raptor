"""Portable dependencies of delivered review context, never verification evidence.

These records narrow reuse of a review. They do not establish caller coverage.
Local file stamps are used only during a freshness check, never persisted.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.refutation_source import capture_source_identity
from core.json import dumps_canonical

MAX_SOURCES = 32
MAX_SNAPSHOT_BYTES = 16 * 1024
MAX_FILE_CHARS = 512
_ROLE = "review-context-inputs"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REFUSED = "review_context_inputs_not_current"


def _source(value: object) -> tuple[str, str] | None:
    if not isinstance(value, dict):
        return None
    file, digest = value.get("file"), value.get("sha256")
    if not isinstance(file, str) or not isinstance(digest, str):
        return None
    if not file or len(file) > MAX_FILE_CHARS or not _DIGEST.fullmatch(digest):
        return None
    # Only canonical portable relative names; confinement is checked again on read.
    if (file.startswith("/") or "\\" in file or ":" in file
            or any(ord(char) < 32 or ord(char) == 127 for char in file)
            or any(part in ("", ".", "..") for part in file.split("/"))):
        return None
    return file, digest


def _snapshot(sources: set[tuple[str, str]], complete: bool) -> dict:
    rows: list[dict[str, str]] = []
    result = {"version": 1, "role": _ROLE, "complete": complete, "sources": rows}
    files: dict[str, str] = {}
    for file, digest in sorted(sources):
        if file in files and files[file] != digest:
            result["complete"] = False
        files[file] = digest
        if len(rows) >= MAX_SOURCES:
            result["complete"] = False
            continue
        rows.append({"file": file, "sha256": digest})
        # Reserve the longer false spelling even if a later row causes loss.
        size_record = {**result, "complete": False}
        if len(json.dumps(size_record, ensure_ascii=True, separators=(",", ":")).encode()) > MAX_SNAPSHOT_BYTES:
            rows.pop()
            result["complete"] = False
    return result


def _decode(value: object) -> tuple[set[tuple[str, str]], bool]:
    if not isinstance(value, dict):
        return set(), False
    complete = (type(value.get("version")) is int and value.get("version") == 1
                and value.get("role") == _ROLE and value.get("complete") is True
                and set(value) == {"version", "role", "complete", "sources"})
    rows = value.get("sources")
    if not isinstance(rows, list):
        return set(), False
    sources: set[tuple[str, str]] = set()
    for row in rows:
        source = _source(row)
        if source is None or not isinstance(row, dict) or set(row) != {"file", "sha256"}:
            complete = False
        if source is not None:
            sources.add(source)
    bounded = _snapshot(sources, complete and len(rows) <= MAX_SOURCES)
    return {(row["file"], row["sha256"]) for row in bounded["sources"]}, bounded["complete"]


def context_inputs_from_delivery(delivery: object, origin: KnowledgeOrigin) -> dict | None:
    """Bind actual caller deliveries and their primary source to portable bytes."""
    if not isinstance(delivery, list):
        return _snapshot(set(), False)
    sources: set[tuple[str, str]] = set()
    delivered = False
    complete = True
    for row in delivery:
        if not isinstance(row, dict) or type(row.get("delivered")) is not bool:
            complete = False
            continue
        if row["delivered"] is not True:
            continue
        delivered = True
        if row.get("role") != "context_delivery_not_verification":
            complete = False
        materials = row.get("source_materials")
        if not isinstance(materials, list) or not materials:
            complete = False
            continue
        for material in materials:
            source = _source(material)
            if source is None:
                complete = False
            else:
                sources.add(source)
    if not delivered and complete:
        return None
    identity = getattr(origin, "source_identity", None)
    primary_source = _source({"file": getattr(origin, "file", None),
                       "sha256": getattr(identity, "sha256", None)})
    if primary_source is None:
        complete = False
    else:
        sources.add(primary_source)
    return _snapshot(sources, complete)


def merge_context_inputs(*snapshots: object) -> dict | None:
    """Union dependencies without allowing absence to erase unknown inputs."""
    sources: set[tuple[str, str]] = set()
    complete = True
    present = False
    for snapshot in snapshots:
        if snapshot is None:
            continue
        present = True
        entries, valid = _decode(snapshot)
        sources.update(entries)
        complete = complete and valid
    return _snapshot(sources, complete) if present else None


def context_inputs_current(snapshot: object, root: str | Path | None) -> tuple[bool, str]:
    """Check full bytes and an interval barrier; absence retains legacy behaviour."""
    if snapshot is None:
        return True, ""
    sources, complete = _decode(snapshot)
    if not complete or root is None or not sources:
        return False, _REFUSED
    identities = {}
    try:
        for file, digest in sorted(sources):
            identity = capture_source_identity(root, file)
            if identity is None or identity.sha256 != digest:
                return False, _REFUSED
            identities[file] = identity
        for file, identity in identities.items():
            if capture_source_identity(root, file) != identity:
                return False, _REFUSED
    except (OSError, ValueError, TypeError, RuntimeError):
        return False, _REFUSED
    return True, ""


def context_inputs_digest(snapshot: object) -> str | None:
    """Name a complete canonical dependency set, never a verification result."""
    if snapshot is None:
        return None
    sources, complete = _decode(snapshot)
    if not complete or not sources:
        return None
    canonical = _snapshot(sources, True)
    return hashlib.sha256(dumps_canonical(canonical).encode()).hexdigest()
