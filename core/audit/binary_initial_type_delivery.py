"""Invocation-local fitting of initial recovered types, never proof authority.

The formatter supplies these rows through its owned callback. Compatibility
context fields alone cannot establish whether a type reached an invocation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256

from core.json import dumps_canonical

from .binary_review_scope import BinaryKnowledgeOrigin

_ROLE = "binary-initial-type-delivery-only"
_ROW_KEYS = frozenset(("schema_version", "role", "subject", "definition_sha256", "status", "reason"))
_REASONS = {"delivered": frozenset(("rendered",)),
            "omitted": frozenset(("glance_packet", "type_definitions_not_fitted"))}
_Definition = tuple[str, str]
_Entry = tuple[str, str, str, str]


def _definitions(ctx: dict) -> tuple[_Definition, ...] | None:
    if ctx.get("is_binary") is not True:
        return None
    rows = ctx.get("type_definitions")
    if type(rows) is not list or not rows:
        return None
    result = []
    subjects = set()
    for row in rows:
        if (type(row) is not dict or type(row.get("name")) is not str
                or type(row.get("file")) is not str or type(row.get("line")) is not int
                or type(row.get("source")) is not str or row["name"] in subjects):
            return None
        subjects.add(row["name"])
        try:
            material = dumps_canonical([row["name"], row["file"], row["line"], row["source"]])
            digest = sha256(material.encode("utf-8")).hexdigest()
        except (TypeError, ValueError, UnicodeError):
            return None
        result.append((row["name"], digest))
    return tuple(result)


def initial_type_delivery_rows(ctx: dict, kept, *, omission_reason=None) -> list[dict]:
    """Describe actual retained sections; no callback means unknown delivery."""
    definitions = _definitions(ctx)
    if definitions is None or isinstance(kept, (str, bytes, dict)):
        return []
    try:
        labels = tuple(getattr(section, "label", None) for section in kept)
    except TypeError:
        return []
    if any(type(label) is not str for label in labels):
        return []
    delivered = "type_definitions" in labels
    reason = ("rendered" if delivered else "glance_packet" if omission_reason == "glance_packet"
              else "type_definitions_not_fitted")
    return [{"schema_version": 1, "role": _ROLE, "subject": subject,
             "definition_sha256": digest, "status": "delivered" if delivered else "omitted",
             "reason": reason} for subject, digest in definitions]


@dataclass(frozen=True)
class InitialBinaryTypeInventory:
    """Original subject ownership, even if a borrowed context later loses it."""

    origin: BinaryKnowledgeOrigin
    _subjects: tuple[str, ...] | None = field(repr=False)
    _definitions: tuple[_Definition, ...] | None = field(repr=False)

    def contains(self, subject: str) -> bool:
        return self._subjects is None or subject in self._subjects


def capture_initial_type_inventory(ctx: dict, *, origin: BinaryKnowledgeOrigin) -> InitialBinaryTypeInventory | None:
    if (not isinstance(origin, BinaryKnowledgeOrigin) or ctx.get("is_binary") is not True
            or not _same_occurrence(ctx, origin)):
        return None
    rows = ctx.get("type_definitions", [])
    subjects = (tuple(row["name"] for row in rows)
                if type(rows) is list and all(type(row) is dict and type(row.get("name")) is str
                                             for row in rows) else None)
    return InitialBinaryTypeInventory(origin, subjects, _definitions(ctx))


@dataclass(frozen=True)
class InitialBinaryTypeDelivery:
    """Original fitting under one binary observation, not current source proof."""

    origin: BinaryKnowledgeOrigin
    _entries: tuple[_Entry, ...] = field(repr=False)

    def records(self) -> list[dict]:
        """Return fresh disclosure rows without lending mutable retained state."""
        return [{"schema_version": 1, "role": _ROLE, "subject": name,
                 "definition_sha256": digest, "status": status, "reason": reason}
                for name, digest, status, reason in self._entries]

    def permits_omission(self, subject: str, ctx: dict, origin: BinaryKnowledgeOrigin) -> bool:
        if (not isinstance(origin, BinaryKnowledgeOrigin) or origin != self.origin
                or type(subject) is not str or not _same_occurrence(ctx, origin)):
            return False
        definitions = _definitions(ctx)
        if definitions is None or definitions != tuple((name, digest) for name, digest, _, _ in self._entries):
            return False
        return any(name == subject and status == "omitted" for name, _, status, _ in self._entries)


def capture_initial_type_delivery(
    rows: object, *, origin: BinaryKnowledgeOrigin, ctx: dict,
    inventory: InitialBinaryTypeInventory | None = None,
) -> InitialBinaryTypeDelivery | None:
    """Freeze exact formatter rows after the caller validates invocation ownership."""
    if inventory is not None and (not isinstance(inventory, InitialBinaryTypeInventory)
                                  or inventory.origin != origin):
        return None
    definitions = inventory._definitions if inventory is not None else _definitions(ctx)
    if (not isinstance(origin, BinaryKnowledgeOrigin) or definitions is None
            or not _same_occurrence(ctx, origin)
            or type(rows) is not list or len(rows) != len(definitions)):
        return None
    entries = []
    for row, (subject, digest) in zip(rows, definitions, strict=True):
        if (type(row) is not dict or set(row) != _ROW_KEYS
                or type(row.get("schema_version")) is not int or row["schema_version"] != 1
                or type(row.get("role")) is not str or row["role"] != _ROLE
                or type(row.get("subject")) is not str or row["subject"] != subject
                or type(row.get("definition_sha256")) is not str or row["definition_sha256"] != digest
                or type(row.get("status")) is not str or row["status"] not in _REASONS
                or type(row.get("reason")) is not str or row["reason"] not in _REASONS[row["status"]]):
            return None
        entries.append((subject, digest, row["status"], row["reason"]))
    return InitialBinaryTypeDelivery(origin, tuple(entries))


def _same_occurrence(ctx: dict, origin: BinaryKnowledgeOrigin) -> bool:
    return ((ctx.get("file"), ctx.get("function")) == (origin.file, origin.function)
            and type(ctx.get("line_start")) is int and ctx["line_start"] == origin.line_start)
