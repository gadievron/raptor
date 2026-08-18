"""Struct-field co-accessor index for concurrency analysis.

Builds an index of which functions access which struct fields, and
under what locking discipline.  Used to surface "these other functions
touch the same fields under different locking" context for the LLM's
concurrency review.

Two backends:
  - Joern CPG (precise): queries the code property graph for
    memberAccess nodes with enclosing function and lock context.
  - Source regex (fallback): scans function source for ``->field``
    patterns and lock/unlock calls.  Less precise but works without
    Joern.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set

logger = logging.getLogger(__name__)


@dataclass
class AccessorRecord:
    """One function's access to a struct field."""
    function: str
    file: str
    field: str
    lock_held: str = ""    # lock name/type if any, or ""
    line: int = 0


@dataclass
class CoAccessorGroup:
    """A struct field accessed by multiple functions with different locking."""
    field: str
    accessors: list = field(default_factory=list)
    lock_conflict: bool = False

    @property
    def description(self) -> str:
        funcs = [a.function for a in self.accessors]
        locked = [a for a in self.accessors if a.lock_held]
        unlocked = [a for a in self.accessors if not a.lock_held]
        if locked and unlocked:
            locked_names = ", ".join(a.function for a in locked[:3])
            unlocked_names = ", ".join(a.function for a in unlocked[:3])
            return (
                f"`{self.field}` accessed under lock by {locked_names} "
                f"but without lock by {unlocked_names}"
            )
        unique_locks = {a.lock_held for a in locked}
        if len(unique_locks) > 1:
            parts = []
            for lock in sorted(unique_locks):
                names = [a.function for a in locked if a.lock_held == lock]
                parts.append(f"{', '.join(names[:2])} (under {lock})")
            return f"`{self.field}` accessed under different locks: {'; '.join(parts)}"
        n = len(funcs)
        names = ", ".join(funcs[:4])
        suffix = f" (+{n - 4} more)" if n > 4 else ""
        return f"`{self.field}` accessed by {names}{suffix}"


_FIELD_ACCESS_RE = re.compile(
    r"(?:\w+)\s*(?:->|\.)\s*(\w+)",
)

_LOCK_CALL_RE = re.compile(
    r"\b(mutex_lock|mutex_lock_interruptible|mutex_lock_killable"
    r"|spin_lock|spin_lock_irq|spin_lock_irqsave|spin_lock_bh"
    r"|read_lock|write_lock|down_read|down_write"
    r"|rcu_read_lock|rw_lock"
    r"|pthread_mutex_lock"
    r"|sync\.(?:Mutex|RWMutex)\.(?:Lock|RLock)"
    r"|\.acquire)\s*\(",
    re.I,
)

_UNLOCK_CALL_RE = re.compile(
    r"\b(mutex_unlock|spin_unlock|spin_unlock_irq|spin_unlock_irqrestore"
    r"|spin_unlock_bh|read_unlock|write_unlock|up_read|up_write"
    r"|rcu_read_unlock|rw_unlock"
    r"|pthread_mutex_unlock"
    r"|\.Unlock|\.RUnlock"
    r"|\.release)\s*\(",
    re.I,
)

_LOCK_NAME_RE = re.compile(
    r"\b(?:mutex_lock|spin_lock\w*|down_read|down_write"
    r"|read_lock|write_lock|rcu_read_lock"
    r"|pthread_mutex_lock)\s*\(\s*&?\s*(\w+(?:->\w+)*)",
)

_NOISE_FIELDS = frozenset({
    "next", "prev", "head", "tail", "data", "len", "size", "count",
    "type", "flags", "status", "state", "ops", "name", "list",
    "lock", "mutex", "spinlock", "refcount", "ref",
})

_MIN_FIELD_LEN = 3


def build_index_from_source(
    gaps: Sequence[Dict[str, Any]],
) -> Dict[str, List[AccessorRecord]]:
    """Build struct-field accessor index from function source code.

    Scans each function's source for ``->field`` / ``.field`` patterns
    and determines whether the access happens under a lock.

    Returns: ``{"field_name": [AccessorRecord, ...]}``
    """
    index: Dict[str, List[AccessorRecord]] = {}

    for gap in gaps:
        func_name = gap.get("name", "")
        file_path = gap.get("file", "")
        source = gap.get("source", "")
        if not (func_name and file_path and source):
            continue

        fields = _extract_fields(source)
        if not fields:
            continue

        lock_name = _detect_lock(source)

        for f in fields:
            record = AccessorRecord(
                function=func_name,
                file=file_path,
                field=f,
                lock_held=lock_name,
            )
            index.setdefault(f, []).append(record)

    return index


def build_index_from_joern(
    server: Any,
    *,
    timeout: int = 90,
) -> Dict[str, List[AccessorRecord]]:
    """Build struct-field accessor index via Joern CPG query.

    Queries the loaded CPG for all member access expressions,
    groups by field name, and annotates with enclosing function
    and lock context.
    """
    query = (
        'cpg.call.where(_.name(".*->.*|.*\\\\..*"))'
        '.map(c => (c.method.head.name, c.method.head.filename, '
        'c.name, c.lineNumber.headOption.getOrElse(-1)))'
        '.l'
    )

    try:
        result = server.query(query, timeout=timeout)
    except Exception:
        logger.debug("joern struct-field query failed", exc_info=True)
        return {}

    if not result or result.errors:
        logger.debug(
            "joern struct-field query returned no results or errors: %s",
            result.errors if result else "no result",
        )
        return {}

    index: Dict[str, List[AccessorRecord]] = {}
    for row in (result.data or []):
        if not isinstance(row, (list, tuple)) or len(row) < 4:
            continue
        func_name, file_path, access_name, line = row
        parts = access_name.rsplit(".", 1) if "." in access_name else access_name.rsplit("->", 1)
        if len(parts) < 2:
            continue
        field_name = parts[-1]
        if not field_name or len(field_name) < _MIN_FIELD_LEN:
            continue
        if field_name in _NOISE_FIELDS:
            continue

        record = AccessorRecord(
            function=str(func_name),
            file=str(file_path),
            field=field_name,
            line=int(line) if isinstance(line, (int, float)) else 0,
        )
        index.setdefault(field_name, []).append(record)

    return index


def get_co_accessors(
    index: Dict[str, List[AccessorRecord]],
    function: str,
    file: str,
    *,
    min_accessors: int = 2,
    same_file_only: bool = False,
) -> List[CoAccessorGroup]:
    """Find fields accessed by both the given function and others.

    Returns groups where the reviewed function and at least one other
    function access the same field, prioritising groups with lock
    conflicts.
    """
    groups: list[CoAccessorGroup] = []

    for field_name, records in index.items():
        mine = [r for r in records if r.function == function and r.file == file]
        if not mine:
            continue

        others = [
            r for r in records
            if not (r.function == function and r.file == file)
        ]
        if same_file_only:
            others = [r for r in others if r.file == file]

        unique_funcs = {r.function for r in others}
        if len(unique_funcs) < min_accessors - 1:
            continue

        deduped = _dedupe_accessors(mine + others)

        my_locks = {r.lock_held for r in mine}
        other_locks = {r.lock_held for r in others}
        has_conflict = bool(
            (my_locks - {""}) != (other_locks - {""})
            or ("" in my_locks and other_locks - {""})
            or ("" in other_locks and my_locks - {""})
        )

        groups.append(CoAccessorGroup(
            field=field_name,
            accessors=deduped,
            lock_conflict=has_conflict,
        ))

    groups.sort(key=lambda g: (not g.lock_conflict, -len(g.accessors)))
    return groups


def format_co_accessor_context(
    groups: List[CoAccessorGroup],
    *,
    max_groups: int = 5,
) -> Optional[str]:
    """Format co-accessor groups for injection into the LLM review context."""
    if not groups:
        return None

    parts = ["[Struct-field co-accessor analysis]"]
    for g in groups[:max_groups]:
        prefix = "[LOCK CONFLICT] " if g.lock_conflict else ""
        parts.append(f"  - {prefix}{g.description}")
    if len(groups) > max_groups:
        parts.append(f"  - ... and {len(groups) - max_groups} more")
    return "\n".join(parts)


def _extract_fields(source: str) -> Set[str]:
    """Extract struct field names from ``->field`` and ``.field`` patterns."""
    fields: set[str] = set()
    for m in _FIELD_ACCESS_RE.finditer(source):
        f = m.group(1)
        if len(f) >= _MIN_FIELD_LEN and f not in _NOISE_FIELDS:
            fields.add(f)
    return fields


def _detect_lock(source: str) -> str:
    """Detect if the function holds a lock, return the lock name or ""."""
    lock_m = _LOCK_CALL_RE.search(source)
    if not lock_m:
        return ""
    name_m = _LOCK_NAME_RE.search(source)
    if name_m:
        return name_m.group(1)
    return lock_m.group(1)


def _dedupe_accessors(records: List[AccessorRecord]) -> List[AccessorRecord]:
    """Remove duplicate (function, file) entries, keep first."""
    seen: set[tuple[str, str]] = set()
    result: list[AccessorRecord] = []
    for r in records:
        key = (r.function, r.file)
        if key not in seen:
            seen.add(key)
            result.append(r)
    return result
