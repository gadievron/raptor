"""Operator-annotation populator for LabeledAttempt records.

Operator-driven mutator for the
failure-mode field on existing records, atomic + path-traversal defended.
"Populated by ... operator annotation (after-the-fact triage)."

Records are normally append-only. Annotation is the explicit
exception: an operator triaging a record can refine its
``failure_mode`` (or clear it) without producing a new record. The
write is atomic (write-temp + rename), and a consistency check
mirrors the dataclass's __post_init__ so the on-disk state can't
diverge from what construction would allow.

This is a thin, focused mutator — not a general-purpose record
editor. Use :func:`set_failure_mode` for the one supported field;
other fields stay immutable so the append-only assumption holds
for everything else.
"""

from __future__ import annotations

import json

from core.atomic_fs import write_text_atomically

from .types import FailureMode, LabeledAttempt
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["set_failure_mode"]


def _atomic_replace(path: Path, payload: str) -> None:
    """Write ``payload`` to a same-directory temp + rename onto
    ``path``. Atomic under POSIX rename semantics."""
    # Atomic write: operator triage rewrites an existing labeled_attempt
    # record; a torn write would corrupt the JSON and hide the record
    # from downstream aggregation. Same-tier reasoning as
    # core/annotations/storage.py — reuse the shared primitive.
    write_text_atomically(path, payload)


def set_failure_mode(
    record_path: Path,
    mode: FailureMode | None,
) -> LabeledAttempt:
    """Update ``record_path``'s ``failure_mode`` field in place.

    Reads the record, applies the new mode, validates the result via
    LabeledAttempt's own construction (so the success+failure_mode
    inconsistency check fires here too), and writes back atomically.

    Returns the updated :class:`LabeledAttempt` so callers can chain
    further inspection.

    Raises:
      * ``FileNotFoundError`` — record_path doesn't exist.
      * ``ValueError`` — the resulting record would be inconsistent
        (e.g. setting any failure_mode on an ``outcome='success'``
        record). The on-disk file is NOT modified in this case.
    """
    if not record_path.is_file():
        msg = f"set_failure_mode: not a file: {record_path}"
        raise FileNotFoundError(msg)
    try:
        blob = json.loads(record_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        msg = (
            f"set_failure_mode: {record_path} is not valid JSON: "
            f"{e.msg} at line {e.lineno} col {e.colno}. "
            f"The record may be corrupt or the path may be a stale "
            f"symlink — investigate before retrying."
        )
        raise ValueError(msg) from None
    if not isinstance(blob, dict):
        msg = (
            f"set_failure_mode: {record_path} contains "
            f"{type(blob).__name__}, expected a JSON object"
        )
        raise ValueError(msg)
    blob["failure_mode"] = mode.value if mode is not None else None
    # Construct first to validate; reject before any write.
    updated = LabeledAttempt.from_dict(blob)
    _atomic_replace(record_path, json.dumps(updated.to_dict(), indent=2))
    return updated
