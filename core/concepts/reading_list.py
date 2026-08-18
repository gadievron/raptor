"""Shared reading list for demand-driven concept learning.

Any RAPTOR command that encounters an unfamiliar construct can queue
a reading-list item.  ``/understand --study`` (or an inline study
pass) drains the queue and resolves items against the domain model.

The reading list is a shared primitive — not owned by any single
consumer.  /audit, /patch, /exploit, /validate, /understand all
produce and consume items through the same interface.

Persistence: JSON file in ``$OUTPUT_DIR/reading-list.json`` (per-run)
or ``<project>/concepts/reading-list.json`` (per-project).
"""

from __future__ import annotations

import dataclasses
import json
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

# ------------------------------------------------------------------
# Priority
# ------------------------------------------------------------------

class Priority(str, Enum):
    CRITICAL = "critical"  # blocks the consumer's current task
    HIGH = "high"          # strongly affects analysis quality
    NORMAL = "normal"      # would improve analysis
    LOW = "low"            # nice to have


class Resolution(str, Enum):
    IDENTIFIER = "identifier"  # mechanical: grep + type-ref index
    CONCEPT = "concept"        # semantic: LLM seeds identifiers first


# ------------------------------------------------------------------
# Reading list item
# ------------------------------------------------------------------

@dataclass
class ReadingListItem:
    """One thing a consumer needs studied before it can proceed."""

    id: str
    question: str
    source_command: str  # e.g. "/audit", "/patch", "/exploit"
    source_file: str = ""
    source_line: int | None = None
    source_function: str = ""
    source_hash: str = ""
    priority: str = Priority.NORMAL.value
    resolution: str = Resolution.IDENTIFIER.value
    context: str = ""
    resolved: bool = False
    resolved_concept_id: str | None = None
    resolved_at: float | None = None
    # Terminal "could not be verified" state — distinct from resolved.
    # An unresolvable item was attempted and cannot be answered from
    # the source (dynamic dispatch, monkey-patching, external
    # dependency, unsupported language).  Consumers must NOT treat it
    # as resolved-clean: the assumption stays unverified, with the
    # reason recorded.  Excluded from pending() so it is never
    # re-studied.
    unresolvable: bool = False
    unresolvable_reason: str = ""

    def resolve(self, concept_id: str) -> None:
        self.resolved = True
        self.resolved_concept_id = concept_id
        self.resolved_at = time.time()

    def mark_unresolvable(self, reason: str) -> None:
        self.unresolvable = True
        self.unresolvable_reason = reason
        self.resolved_at = time.time()


# ------------------------------------------------------------------
# Reading list
# ------------------------------------------------------------------

@dataclass
class ReadingList:
    """Queue of items that need concept extraction."""

    items: list[ReadingListItem] = field(default_factory=list)
    _path: Path | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ----- queue operations --------------------------------------

    def queue(self, item: ReadingListItem) -> None:
        _ORDER = [Priority.CRITICAL, Priority.HIGH, Priority.NORMAL, Priority.LOW]
        with self._lock:
            for existing in self.items:
                if existing.question == item.question and not existing.resolved:
                    try:
                        if _ORDER.index(Priority(item.priority)) < _ORDER.index(Priority(existing.priority)):
                            existing.priority = item.priority
                    except ValueError:
                        pass
                    return
            self.items.append(item)

    def pending(self) -> list[ReadingListItem]:
        return [
            i for i in self.items if not i.resolved and not i.unresolvable
        ]

    def resolved(self) -> list[ReadingListItem]:
        return [i for i in self.items if i.resolved]

    def unresolvable_items(self) -> list[ReadingListItem]:
        return [i for i in self.items if i.unresolvable]

    def drain(self, max_items: int | None = None) -> list[ReadingListItem]:
        """Return pending items in priority order, optionally limited."""
        order = [Priority.CRITICAL, Priority.HIGH, Priority.NORMAL, Priority.LOW]
        pending = sorted(
            self.pending(),
            key=lambda i: order.index(Priority(i.priority))
            if i.priority in [p.value for p in Priority]
            else len(order),
        )
        if max_items is not None:
            return pending[:max_items]
        return pending

    def resolve(self, item_id: str, concept_id: str) -> bool:
        for item in self.items:
            if item.id == item_id:
                item.resolve(concept_id)
                return True
        return False

    def mark_unresolvable(self, item_id: str, reason: str) -> bool:
        """Mark an item as attempted-but-unanswerable.

        The item leaves pending() permanently but is NEVER reported as
        resolved — the assumption it encodes stays unverified.
        """
        for item in self.items:
            if item.id == item_id:
                if item.resolved:
                    return False
                item.mark_unresolvable(reason)
                return True
        return False

    def by_command(self, command: str) -> list[ReadingListItem]:
        return [i for i in self.items if i.source_command == command]

    def __len__(self) -> int:
        return len(self.items)

    # ----- persistence -------------------------------------------

    def save(self, path: Path | None = None) -> None:
        p = path or self._path
        if p is None:
            raise ValueError("no path specified")
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(p.parent), suffix=".tmp", prefix=".reading-list-",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"items": [asdict(i) for i in self.items]}, f, indent=2)
                f.write("\n")
            Path(tmp_name).rename(p)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise
        self._path = p

    @classmethod
    def load(cls, path: Path) -> ReadingList:
        if not path.exists():
            return cls(_path=path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return cls(_path=path)
        if not isinstance(raw, dict):
            return cls(_path=path)
        valid_keys = {f.name for f in dataclasses.fields(ReadingListItem)}
        items = [
            ReadingListItem(**{k: v for k, v in i.items() if k in valid_keys})
            for i in raw.get("items", [])
        ]
        return cls(items=items, _path=path)
