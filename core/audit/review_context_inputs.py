"""Portable dependencies of delivered review context, never verification evidence.

These records narrow reuse of a review. They do not establish caller coverage.
Local file stamps are used only during a freshness check, never persisted.
"""

from __future__ import annotations

from collections.abc import Iterable
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
_ROOT_LABEL = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_REFUSED = "review_context_inputs_not_current"
_Source = tuple[str, str, str]


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


def _rooted_source(value: object, version: int) -> _Source | None:
    source = _source(value)
    if source is None or not isinstance(value, dict):
        return None
    label = value.get("root") if version == 2 else "target"
    if not isinstance(label, str) or not _ROOT_LABEL.fullmatch(label):
        return None
    return label, source[0], source[1]


def _snapshot(sources: set[_Source], complete: bool, *, version: int = 1) -> dict:
    rows: list[dict[str, str]] = []
    result = {"version": version, "role": _ROLE, "complete": complete, "sources": rows}
    files: dict[tuple[str, str], str] = {}
    for label, file, digest in sorted(sources):
        key = label, file
        if key in files and files[key] != digest:
            result["complete"] = False
        files[key] = digest
        if len(rows) >= MAX_SOURCES:
            result["complete"] = False
            continue
        row = {"file": file, "sha256": digest}
        if version == 2:
            row = {"root": label, **row}
        rows.append(row)
        # Reserve the longer false spelling even if a later row causes loss.
        size_record = {**result, "complete": False}
        if len(json.dumps(size_record, ensure_ascii=True, separators=(",", ":")).encode()) > MAX_SNAPSHOT_BYTES:
            rows.pop()
            result["complete"] = False
    return result


def _decode(value: object) -> tuple[set[_Source], bool, int]:
    if not isinstance(value, dict):
        return set(), False, 1
    raw_version = value.get("version")
    version = 2 if type(raw_version) is int and raw_version == 2 else 1
    complete = (type(raw_version) is int and raw_version in (1, 2)
                and value.get("role") == _ROLE and value.get("complete") is True
                and set(value) == {"version", "role", "complete", "sources"})
    rows = value.get("sources")
    if not isinstance(rows, list):
        return set(), False, version
    sources: set[_Source] = set()
    keys = {"root", "file", "sha256"} if version == 2 else {"file", "sha256"}
    for row in rows:
        source = _rooted_source(row, version)
        if source is None or not isinstance(row, dict) or set(row) != keys:
            complete = False
        if source is not None:
            sources.add(source)
    bounded = _snapshot(sources, complete and len(rows) <= MAX_SOURCES, version=version)
    return ({(row.get("root", "target"), row["file"], row["sha256"])
             for row in bounded["sources"]}, bounded["complete"], version)


def context_inputs_from_delivery(delivery: object, origin: KnowledgeOrigin) -> dict | None:
    """Bind actual caller deliveries and their primary source to portable bytes."""
    if not isinstance(delivery, list):
        return _snapshot(set(), False)
    sources: set[_Source] = set()
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
                sources.add(("target", *source))
    if not delivered and complete:
        return None
    identity = getattr(origin, "source_identity", None)
    primary_source = _source({"file": getattr(origin, "file", None),
                              "sha256": getattr(identity, "sha256", None)})
    if primary_source is None:
        complete = False
    else:
        sources.add(("target", *primary_source))
    return _snapshot(sources, complete)


def context_inputs_from_sources(sources: Iterable[tuple[str, str, str]], *, complete: bool = True) -> dict:
    """Retain already captured root-qualified identities without reading files."""
    entries: set[_Source] = set()
    known = complete is True
    try:
        for row in sources:
            if not isinstance(row, (tuple, list)) or len(row) != 3:
                known = False
                continue
            source = _rooted_source({"root": row[0], "file": row[1], "sha256": row[2]}, 2)
            if source is None:
                known = False
            else:
                entries.add(source)
    except (TypeError, ValueError, RuntimeError):
        known = False
    return _snapshot(entries, known, version=2)


def merge_context_inputs(*snapshots: object) -> dict | None:
    """Union dependencies without allowing absence to erase unknown inputs."""
    sources: set[_Source] = set()
    complete = True
    present = False
    version = 1
    for snapshot in snapshots:
        if snapshot is None:
            continue
        present = True
        entries, valid, incoming_version = _decode(snapshot)
        sources.update(entries)
        complete = complete and valid
        version = max(version, incoming_version)
    return _snapshot(sources, complete, version=version) if present else None


def context_inputs_current(
    snapshot: object, root: str | Path | None, *, source_roots: dict[str, Path] | None = None,
) -> tuple[bool, str]:
    """Check bytes under current trusted roots; never resolve roots from a row."""
    if snapshot is None:
        return True, ""
    sources, complete, _ = _decode(snapshot)
    if not complete or root is None or not sources:
        return False, _REFUSED
    # A supplied map can add explicit roots, but cannot replace the target.
    identities = {}
    try:
        configured = dict(source_roots) if isinstance(source_roots, dict) else {}
        configured["target"] = Path(root)
        for label, file, digest in sorted(sources):
            source_root = configured.get(label)
            if source_root is None:
                return False, _REFUSED
            identity = capture_source_identity(source_root, file)
            if identity is None or identity.sha256 != digest:
                return False, _REFUSED
            identities[label, file] = (source_root, identity)
        for (_, file), (source_root, identity) in identities.items():
            if capture_source_identity(source_root, file) != identity:
                return False, _REFUSED
    except (OSError, ValueError, TypeError, RuntimeError):
        return False, _REFUSED
    return True, ""


def context_inputs_digest(snapshot: object) -> str | None:
    """Name a complete canonical dependency set, never a verification result."""
    if snapshot is None:
        return None
    sources, complete, version = _decode(snapshot)
    if not complete or not sources:
        return None
    canonical = _snapshot(sources, True, version=version)
    return hashlib.sha256(dumps_canonical(canonical).encode()).hexdigest()


def context_inputs_record_digest(snapshot: object) -> str | None:
    """Identify an exact bounded record, including an explicitly incomplete one.

    This digest does not admit reuse. It preserves the stated completeness and
    duplicate/conflicting rows; only row order and JSON key order are canonical.
    """
    if (not isinstance(snapshot, dict) or type(snapshot.get("version")) is not int
            or snapshot.get("version") not in (1, 2)
            or snapshot.get("role") != _ROLE or type(snapshot.get("complete")) is not bool
            or set(snapshot) != {"version", "role", "complete", "sources"}):
        return None
    rows = snapshot.get("sources")
    if not isinstance(rows, list) or len(rows) > MAX_SOURCES:
        return None
    version = snapshot["version"]
    keys = {"root", "file", "sha256"} if version == 2 else {"file", "sha256"}
    if any(not isinstance(row, dict) or set(row) != keys or _rooted_source(row, version) is None
           for row in rows):
        return None
    canonical = {**snapshot, "sources": sorted(rows, key=lambda row: (
        row.get("root", "target"), row["file"], row["sha256"]))}
    encoded = dumps_canonical(canonical).encode()
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        return None
    return hashlib.sha256(encoded).hexdigest()
