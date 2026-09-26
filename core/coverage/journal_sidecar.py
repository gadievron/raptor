"""Sidecar store for offloaded review-journal row content.

``raptor-audit journal compact --slim-clean`` moves the fat, cold
fields of clean/dormant journal rows (prose ``body``, ``hypotheses``,
and the per-row domain-knowledge snapshot lists
``invariants_available`` / ``domain_concepts_available``) out of
``review-journal.jsonl`` into ``review-journal-bodies.jsonl`` in the
same run directory, leaving a loader-valid STUB row behind. The stub
keeps every verdict/coverage/spend-relevant field inline (key, site,
ts, verdict, source_hash, model, strategies, cost_usd, corrections)
plus a ``body_offload`` pointer: sidecar name, byte offset, record
length, and a content hash of the extracted fields. Claim rows
(finding/suspicious) are never slimmed — their bodies stay inline.

Trust model (mirrors ``core.coverage.journal_mac``): the sidecar
lives in the same target-writable run dir as the journal, so a
record authenticates only through the stub. On a MAC-verified stub
the pointer's ``sha256`` is covered by the row token, so a sidecar
record that hashes to it is the content the compactor wrote; on
unstamped/tampered stubs the hash check is consistency, not
authenticity — exactly the authority the un-slimmed row had. Readers
NEVER treat the pointer's ``sidecar`` value as a path: only the
fixed sidecar name inside the stub's own run dir is opened
(a planted pointer must not steer reads elsewhere).

Fail direction: every resolution failure (missing sidecar, bad
offset, hash mismatch, oversize record) returns ``None`` and the
consumer keeps the stub view — for the one verdict-relevant consumer
(the reuse fold's context-staleness gate) that means refusing the $0
reuse and re-reviewing, never trusting unverifiable context.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import replace
from pathlib import Path
from typing import Any

from core.json import loads
from core.json.utils import dumps_canonical

from .journal import ReviewJournalEntry, _field_types, _value_matches

logger = logging.getLogger(__name__)

#: Fixed sidecar filename beside ``review-journal.jsonl``. Readers
#: open exactly this name in the stub's run dir regardless of what
#: the (attacker-writable) pointer claims.
SIDECAR_FILENAME = "review-journal-bodies.jsonl"

#: Sidecar record schema version.
SIDECAR_SCHEMA_VERSION = 1

#: The journal-row fields the slim tier may offload. Order is the
#: extraction order; membership is the closed set every reader
#: restores from — a field added here needs its own consumer
#: analysis (who reads it from non-claim rows, and what the stub
#: degrade is) before it ships.
OFFLOAD_FIELDS = (
    "body",
    "hypotheses",
    "invariants_available",
    "domain_concepts_available",
)

#: Fields whose offload matters to the reuse fold's context-staleness
#: gate (AR-7): a stub missing these must hydrate (or refuse reuse)
#: before the relevance diff runs.
CONTEXT_FIELDS = frozenset(
    {"invariants_available", "domain_concepts_available"})

#: Per-record read bound — one sidecar record holds a handful of the
#: journal's own per-line-bounded fields, so the journal's line bound
#: is the natural ceiling; a corrupt/hostile offset that lands inside
#: a multi-GiB plant reads at most this much.
_MAX_SIDECAR_RECORD_BYTES = 8 * 1024 * 1024

#: Offset sanity bound (matches the journal loader's whole-file read
#: budget scale): a pointer past this refuses without a seek.
_MAX_SIDECAR_OFFSET = 1 << 40


def fields_sha256(fields: dict[str, Any]) -> str:
    """Content hash binding a stub pointer to its sidecar record:
    sha256 over the canonical JSON of the extracted-fields dict
    (``core.json.utils.dumps_canonical`` — the repo-frozen canonical
    byte form, same as the row MAC's payload hashing)."""
    return hashlib.sha256(
        dumps_canonical(fields).encode("utf-8")).hexdigest()


def offload_pointer(entry: Any) -> dict[str, Any] | None:
    """The entry's ``body_offload`` pointer when it is shaped like
    one, else ``None``. Journal rows are target-writable, so every
    field is vetted before use (the offset especially — it steers a
    seek)."""
    ptr = getattr(entry, "body_offload", None)
    if not isinstance(ptr, dict):
        return None
    offset = ptr.get("offset")
    sha = ptr.get("sha256")
    if not isinstance(offset, int) or isinstance(offset, bool) \
            or not (0 <= offset <= _MAX_SIDECAR_OFFSET):
        return None
    if not isinstance(sha, str) or len(sha) != 64:
        return None
    return ptr


def entry_fields_offloaded(entry: Any) -> frozenset[str]:
    """Names of the fields a stub's pointer claims were offloaded
    (empty set for non-stub rows or malformed pointers)."""
    ptr = offload_pointer(entry)
    if ptr is None:
        return frozenset()
    fields = ptr.get("fields")
    if not isinstance(fields, list):
        return frozenset()
    return frozenset(f for f in fields if isinstance(f, str))


def entry_context_offloaded(entry: Any) -> bool:
    """True when the stub offloaded the domain-knowledge snapshot
    lists the context-staleness gate reads."""
    return bool(entry_fields_offloaded(entry) & CONTEXT_FIELDS)


def resolve_offload(
    out_dir: Path | str, entry: Any,
) -> dict[str, Any] | None:
    """Load and integrity-check the sidecar record for a stub.

    Returns the extracted-fields dict (``{"body": ..., ...}``) or
    ``None`` on any failure — absent/foreign sidecar, out-of-range
    offset, unparseable record, or a record whose canonical content
    hash does not match the stub pointer's (MAC-covered, on verified
    stubs) ``sha256``.
    """
    ptr = offload_pointer(entry)
    if ptr is None:
        return None
    # Fixed name in the stub's own run dir — never the pointer's
    # ``sidecar`` string (attacker-writable; must not steer the read).
    path = Path(out_dir) / SIDECAR_FILENAME
    from core.source import open_regular
    fh = open_regular(path, "rb")
    if fh is None:
        return None
    try:
        with fh:
            try:
                fh.seek(ptr["offset"])
                line = fh.readline(_MAX_SIDECAR_RECORD_BYTES + 1)
            except (OSError, ValueError):
                return None
    except OSError:
        return None
    if not line or len(line) > _MAX_SIDECAR_RECORD_BYTES:
        return None
    try:
        record = loads(line)
    except Exception:  # noqa: BLE001 — sidecar rows are run-dir content; containment boundary
        return None
    if not isinstance(record, dict):
        return None
    fields = record.get("fields")
    if not isinstance(fields, dict):
        return None
    if fields_sha256(fields) != ptr["sha256"]:
        logger.warning(
            "journal sidecar: content hash mismatch at %s offset %d "
            "— refusing the record (stub keeps its offloaded view)",
            path, ptr["offset"],
        )
        return None
    return fields


def hydrate_entry(
    out_dir: Path | str, entry: ReviewJournalEntry,
) -> ReviewJournalEntry | None:
    """A COPY of *entry* with its offloaded fields restored from the
    sidecar, or ``None`` when the record cannot be resolved.

    Non-stub entries return themselves unchanged (cheap no-op).
    Always a copy for stubs: loaded entry objects are shared by the
    journal load path and frozen by contract — hydration must never
    mutate a shared object in place.
    """
    if offload_pointer(entry) is None:
        return entry
    fields = resolve_offload(out_dir, entry)
    if fields is None:
        return None
    known = {
        k: v for k, v in fields.items()
        if k in OFFLOAD_FIELDS and v is not None
    }
    # Type-validate restored values against the dataclass annotations
    # (the journal loader's own mechanical rule): the sidecar is
    # run-dir content, and behind an UNSTAMPED stub the content hash
    # is consistency, not authenticity — a wrong-typed plant (str
    # where a list belongs) must refuse hydration, never flow into
    # consumers that iterate/set() the fields.
    types = _field_types()
    for k, v in known.items():
        if not _value_matches(v, types[k]):
            logger.warning(
                "journal sidecar: offloaded field %r has invalid "
                "type %s — refusing hydration", k, type(v).__name__)
            return None
    return replace(entry, **known)


def reconstruct_row(
    stub_raw: dict[str, Any], record: dict[str, Any],
) -> dict[str, Any]:
    """Rebuild the original journal row DICT from a stub row and its
    sidecar record (the semantic-losslessness contract: equal to the
    original row's parsed dict, so the archived original's MAC token
    verifies over the reconstruction).

    Byte-level reversibility is the ``.pre-slim`` whole-file archive;
    this rebuilds content, not byte order.

    No self-check: this function does NOT verify the stub pointer's
    content hash against *record* (that is :func:`resolve_offload`'s
    job). Callers wanting integrity on the reconstruction get it from
    the archived row MAC — the restored ``integrity_orig`` token
    verifies over the rebuilt row exactly when the content matches
    what the original writer stamped.
    """
    row = dict(stub_raw)
    row.pop("body_offload", None)
    fields = record.get("fields")
    if isinstance(fields, dict):
        for k, v in fields.items():
            if k in OFFLOAD_FIELDS:
                row[k] = v
    row.pop("integrity", None)
    orig_token = record.get("integrity_orig")
    if isinstance(orig_token, str) and orig_token:
        row["integrity"] = orig_token
    return row


__all__ = [
    "CONTEXT_FIELDS",
    "OFFLOAD_FIELDS",
    "SIDECAR_FILENAME",
    "SIDECAR_SCHEMA_VERSION",
    "entry_context_offloaded",
    "entry_fields_offloaded",
    "fields_sha256",
    "hydrate_entry",
    "offload_pointer",
    "reconstruct_row",
    "resolve_offload",
]
