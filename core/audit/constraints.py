"""Constraint data model and JSON storage for cross-function audit.

When the LLM reviews a function and discovers a condition that callers
(or callees) must satisfy, it emits a Constraint.  The orchestrator
persists these in ``constraints.json`` (separate from annotations —
decision: machine-readable store for propagation, annotations carry
the prose).

Constraints propagate through the call graph via the resolver chain
in ``propagation.py``.  Each constraint carries a source hash so the
staleness mechanism can invalidate constraints whose source changed
between audit runs.

Storage: one ``constraints.json`` per audit output directory.  File
is a JSON array of constraint dicts.  Atomic writes via tempfile +
os.replace (same pattern as project_context.py).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Any, TYPE_CHECKING

from ._util import find_function_lines, safe_join
from pathlib import Path

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

CONSTRAINT_KINDS = frozenset({
    "parameter",
    "precondition",
    "postcondition",
    "state",
    "ordering",
})

CONSTRAINT_STATUSES = frozenset({
    "open",
    "verified",
    "refuted",
    "stale",
    "depth_limited",
    "mechanised",
})

PROPAGATION_DIRECTIONS = frozenset({
    "callers",
    "callees",
    "both",
})


@dataclass
class Constraint:
    """A cross-function security constraint emitted during review."""

    function: str
    file: str

    kind: str       # parameter | precondition | postcondition | state | ordering
    target: str     # what's constrained: param name, lock, return value, etc.
    rule: str       # human-readable: "len must be <= 1024"
    violation: str  # what breaks: "stack buffer overflow in 1024-byte buf"

    cwe: str = ""
    direction: str = "callers"
    mechanical_check: str = ""

    source_review: str = ""
    source_hash: str = ""
    status: str = "open"
    depth_reached: int = 0
    propagation_chain: list[str] = field(default_factory=list)

    @property
    def identity(self) -> str:
        """Merge key: same function+kind+target = same constraint."""
        return f"{self.file}:{self.function}:{self.kind}:{self.target}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Constraint:
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)

    def is_taint_expressible(self) -> bool:
        """Whether this constraint can be expressed as a taint query."""
        return self.kind == "parameter"


def load_constraints(out_dir: Path) -> list[Constraint]:
    """Load constraints from constraints.json."""
    path = out_dir / "constraints.json"
    if not path.exists():
        return []
    try:
        with Path(path).open(encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return []
        return [Constraint.from_dict(d) for d in data]
    except (json.JSONDecodeError, OSError, TypeError) as exc:
        logger.warning("failed to load constraints: %s", exc)
        return []


def save_constraints(
    constraints: list[Constraint], out_dir: Path,
) -> None:
    """Atomically write constraints to constraints.json."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "constraints.json"
    data = [c.to_dict() for c in constraints]
    fd, tmp = tempfile.mkstemp(dir=out_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def merge_constraint(
    existing: list[Constraint],
    new: Constraint,
) -> list[Constraint]:
    """Merge a new constraint into an existing list by identity.

    Same identity (file:function:kind:target) -> replace with the new
    one (most recent review wins).  Different identity -> append.
    Returns a new list.

    Uses a dict keyed by identity for O(1) lookup instead of O(n)
    linear scan per merge.
    """
    by_id: dict[str, Constraint] = {}
    order: list[str] = []
    for c in existing:
        cid = c.identity
        if cid not in by_id:
            order.append(cid)
        by_id[cid] = c

    new_id = new.identity
    if new_id not in by_id:
        order.append(new_id)
    by_id[new_id] = new

    return [by_id[k] for k in order]


def refresh_constraint_statuses(
    constraints: list[Constraint],
    target_path: Path,
    checklist: dict[str, Any] | None = None,
) -> list[Constraint]:
    """Mark stale constraints based on source hash changes.

    Uses checklist line numbers for accurate re-hashing when available.
    """
    if not checklist:
        return constraints

    try:
        from core.annotations.storage import compute_function_hash
    except ImportError:
        return constraints

    refreshed = []
    for c in constraints:
        if c.status in ("refuted", "verified", "mechanised"):
            refreshed.append(c)
            continue

        if not c.source_hash:
            refreshed.append(c)
            continue

        source_file = safe_join(target_path, c.file)
        if source_file is None:
            refreshed.append(c)
            continue

        if not source_file.exists():
            c_copy = Constraint.from_dict(c.to_dict())
            c_copy.status = "stale"
            refreshed.append(c_copy)
            continue

        line_start, line_end = find_function_lines(
            checklist, c.file, c.function,
        )
        if not (line_start and line_end):
            refreshed.append(c)
            continue

        current_hash = compute_function_hash(
            source_file, line_start, line_end,
        )
        if current_hash and current_hash != c.source_hash:
            c_copy = Constraint.from_dict(c.to_dict())
            c_copy.status = "stale"
            refreshed.append(c_copy)
        else:
            refreshed.append(c)

    return refreshed


def open_constraints(constraints: list[Constraint]) -> list[Constraint]:
    """Filter to propagation-eligible constraints."""
    return [
        c for c in constraints
        if c.status in ("open", "depth_limited")
    ]


def extract_constraints_from_review(
    review_result: dict[str, Any],
    file_path: str,
    function_name: str,
    source_hash: str = "",
    source_review: str = "",
) -> list[Constraint]:
    """Extract Constraint objects from an LLM review result.

    The review result is expected to have a 'constraints' key with a
    list of dicts matching the Constraint fields (minus file/function
    which are supplied by the caller).
    """
    raw = review_result.get("constraints", [])
    if not isinstance(raw, list):
        return []

    result = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        kind = item.get("kind", "")
        if kind not in CONSTRAINT_KINDS:
            continue
        target = item.get("target", "")
        rule = item.get("rule", "")
        if not (target and rule):
            continue
        direction = item.get("direction", "callers")
        if direction not in PROPAGATION_DIRECTIONS:
            direction = "callers"
        result.append(Constraint(
            function=function_name,
            file=file_path,
            kind=kind,
            target=target,
            rule=rule,
            violation=item.get("violation", ""),
            cwe=item.get("cwe", ""),
            direction=direction,
            mechanical_check=item.get("mechanical_check", ""),
            source_hash=source_hash,
            source_review=source_review,
        ))
    return result
