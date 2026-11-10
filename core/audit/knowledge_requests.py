"""Pipeline-owned knowledge requests from a provisional code review.

These requests ask for information. They carry no confirmation, refutation
or completeness authority, and model-supplied identities are never adopted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal
from uuid import uuid4

from .refutation_source import SourceIdentity


@dataclass(frozen=True)
class KnowledgeOrigin:
    """Snapshot assigned by the review pipeline before dispatch."""

    pass_id: str
    file: str
    function: str
    line_start: int
    line_end: int
    source_identity: SourceIdentity | None


@dataclass(frozen=True)
class KnowledgeRequest:
    request_id: str
    origin: KnowledgeOrigin
    kind: Literal["target_study", "language_reference"]
    subject: str
    context: str
    priority: str
    resolution: str = ""
    entry_id: str | None = None
    source_line: int | None = None


@dataclass(frozen=True)
class RejectedKnowledgeRequest:
    field: str
    index: int | None
    reason: str
    count: int = 1


@dataclass(frozen=True)
class KnowledgeBatch:
    accepted: tuple[KnowledgeRequest, ...]
    rejected: tuple[RejectedKnowledgeRequest, ...]


_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:(?:::|\.)[A-Za-z_][A-Za-z_0-9]*)*")
_QUESTION_START = re.compile(r"(?:does|do|did|is|are|was|were|can|could|would|should|has|have|how|why|what|when|where|which)\s", re.I)
_PRIORITIES = frozenset(("critical", "high", "normal", "low"))
_MAX_PER_FIELD = 16


def _bounded_field_text(item: dict, name: str, limit: int, *, required: bool = True) -> str | None:
    value = item.get(name, "" if not required else None)
    if not isinstance(value, str) or len(value) > limit:
        return None
    value = value.strip()
    return value if value or not required else None


def register_requests(review: object, origin: KnowledgeOrigin) -> KnowledgeBatch:
    """Admit bounded subjects/topics with exact pipeline origin and fresh IDs.

    Legacy question-shaped reading-list items are rejected visibly rather
    than heuristically rewritten or sent to a paid classifier. This cannot
    recognise every semantically misrouted subject; the reviewer schema and
    source-study prompt must also state the boundary.
    """
    if not isinstance(review, dict):
        return KnowledgeBatch((), ())
    accepted = []
    rejected = []
    seen = set()
    fields: tuple[tuple[str, Literal["target_study", "language_reference"]], ...] = (
        ("reading_list", "target_study"), ("language_reference_requests", "language_reference"))
    for field, kind in fields:
        rows = review.get(field, [])
        if not isinstance(rows, list):
            rejected.append(RejectedKnowledgeRequest(field, None, "expected_array"))
            continue
        if len(rows) > _MAX_PER_FIELD:
            rejected.append(RejectedKnowledgeRequest(field, None, "request_limit", len(rows) - _MAX_PER_FIELD))
        for index, item in enumerate(rows[:_MAX_PER_FIELD]):
            def refuse(reason: str) -> None:
                rejected.append(RejectedKnowledgeRequest(field, index, reason))

            if not isinstance(item, dict):
                refuse("expected_object")
                continue
            subject = _bounded_field_text(item, "subject" if kind == "target_study" else "topic", 96 if kind == "target_study" else 512)
            context = _bounded_field_text(item, "context" if kind == "target_study" else "needed_for", 1000, required=False)
            priority = item.get("priority", "normal")
            if subject is None or context is None or not isinstance(priority, str) or priority not in _PRIORITIES:
                refuse("invalid_request_fields")
                continue
            resolution = ""
            entry_id = None
            source_line = None
            if kind == "target_study":
                resolution = item.get("resolution", "identifier")
                if resolution not in ("identifier", "concept"):
                    refuse("invalid_resolution")
                    continue
                if "?" in subject or "\n" in subject or "\r" in subject or _QUESTION_START.match(subject):
                    refuse("study_requires_subject_not_question")
                    continue
                if resolution == "identifier" and not _IDENTIFIER.fullmatch(subject):
                    refuse("invalid_identifier_subject")
                    continue
            else:
                entry_id = _bounded_field_text(item, "entry_id", 96, required=False)
                if entry_id is None:
                    refuse("invalid_reference_id")
                    continue
                entry_id = entry_id or None
                anchor = item.get("source_anchor")
                if anchor is not None:
                    if (not isinstance(anchor, dict)
                            or anchor.get("file") != origin.file
                            or type(anchor.get("line")) is not int
                            or not origin.line_start <= anchor["line"] <= origin.line_end):
                        refuse("anchor_outside_review_material")
                        continue
                    source_line = anchor["line"]
            key = (kind, subject, context, resolution, entry_id, source_line)
            if key in seen:
                refuse("duplicate_request")
                continue
            seen.add(key)
            accepted.append(KnowledgeRequest(
                uuid4().hex, origin, kind, subject, context, priority,
                resolution, entry_id, source_line,
            ))
    return KnowledgeBatch(tuple(accepted), tuple(rejected))
