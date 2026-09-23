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
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

from core.json import save_json


def question_scoped_id(prefix: str, question: str) -> str:
    """Collision-free reading-list item id.

    Ids built from a name or a question PREFIX alone are lossy: two
    DIFFERENT questions about one function shared an id, and the
    id-keyed persistence fold silently destroyed one — the assumption
    it encoded stayed unverified with no record. Suffix a hash of the
    full question so distinct questions never share an id; *prefix*
    keeps ids operator-readable.
    """
    import hashlib

    digest = hashlib.sha256(question.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}.{digest}"

# In-process writer lock for the reading list's load-modify-save
# cycle. The file has MANY concurrent in-process writers (premise
# study questions from parallel review/post-loop passes,
# audit_bridge.queue_reading_list_item, the study consumer's
# unresolvable marking and final save) and each is a read-modify-write
# of the whole JSON file — unserialized, they silently drop each
# other's items. Every writer must hold this lock across its whole
# load→mutate→save cycle (the per-instance ``ReadingList._lock`` only
# serializes mutations of ONE loaded instance, which does nothing for
# two writers holding separate instances of the same file).
# In-process half of the exclusion; the project-level reading list
# (``<project>/concepts/reading-list.json``) has cross-PROCESS writers
# too (concurrent runs of one project), so every load→mutate→save
# window ALSO holds ``core.fs_lock.artifact_lock`` on the file, inside
# this lock (thread lock outer, file lock inner — one order,
# everywhere).
READING_LIST_WRITE_LOCK = threading.Lock()

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
            msg = "no path specified"
            raise ValueError(msg)
        save_json(p, {"items": [asdict(i) for i in self.items]})
        self._path = p

    def save_merged(self, path: Path | None = None) -> None:
        """Save under ``READING_LIST_WRITE_LOCK``, folding in items
        other writers persisted since this instance was loaded.

        For long-lived instances (the study consumer holds one across
        a whole study pass) a plain :meth:`save` would overwrite items
        queued concurrently by other writers. Under the lock, re-load
        the disk state and append any item whose (id, question) this
        instance has not seen; this instance's own mutations
        (resolutions, unresolvable marks) win for identities it knows.
        The fold key carries the question because ids from legacy
        constructors are lossy (name-only / question-prefix): folding
        by id alone silently destroyed a concurrent writer's DISTINCT
        question that happened to share an id.
        """
        from core.fs_lock import artifact_lock

        with READING_LIST_WRITE_LOCK:
            p = path or self._path
            if p is None:
                msg = "no path specified"
                raise ValueError(msg)
            with artifact_lock(p, subject="reading list"):
                disk = ReadingList.load(p)
                with self._lock:
                    known = {(i.id, i.question) for i in self.items}
                    self.items.extend(
                        i for i in disk.items
                        if (i.id, i.question) not in known
                    )
                self.save(p)

    @classmethod
    def load(cls, path: Path) -> ReadingList:
        if not path.exists():
            return cls(_path=path)
        from core.json import load_json
        try:
            # strict=True keeps the historical contract: read errors
            # (OSError) propagate; malformed/oversize degrades to an
            # empty list via the ValueError catch below.
            raw = load_json(path, strict=True, max_bytes=64 * 1024 * 1024)
        except ValueError:
            return cls(_path=path)
        if not isinstance(raw, dict):
            return cls(_path=path)
        valid_keys = {f.name for f in dataclasses.fields(ReadingListItem)}
        items = [
            ReadingListItem(**{k: v for k, v in i.items() if k in valid_keys})
            for i in raw.get("items", [])
        ]
        return cls(items=items, _path=path)
