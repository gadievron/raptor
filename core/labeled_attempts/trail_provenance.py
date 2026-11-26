"""Authorship tokens for run-local ``verified-outcomes.jsonl`` records.

The run-local trail (source 3 of
:func:`core.labeled_attempts.view.collect_outcomes`) is an append-only
JSONL file inside the run output dir — a tree that scanned-target code
and sandboxed children can often write. Pre-stamp, any line there was
taken at face value: a planted ``status="verified"`` record walked
straight into the operator's Confirmed view and into exemplar
retrieval. Producers now stamp each record at write time with an
HMAC-SHA256 token under a per-purpose key, and the reader demotes
records whose token does not verify.

The construction mirrors the witness-manifest stamp
(``core.witness.provenance.stamp_witness_manifest``): the token is a
content MAC over the WHOLE record minus the token key itself, so
nothing in a validly-stamped record can be rewritten under a surviving
token. Deliberately NO run binding — a verified outcome asserts a
location-independent fact, and the token defends AUTHORSHIP (same
doctrine as ``witness_manifest_fields``).

Per-purpose key: ``$XDG_DATA_HOME/raptor/outcome-trail-mac.key`` —
never shared with any other subsystem's key file
(:mod:`core.security.mac_key` doctrine). The key lives outside every
LLM-writable and sandbox-readable tree. A verified token proves the
record was minted by code that could read that key file, nothing
stronger; key confidentiality is the trust anchor.

Failure policy is demote-never-error: no usable key → records persist
unstamped and the reader demotes them to ``inconclusive`` (they drop
out of the Confirmed view and out of VERIFIED-ranked retrieval but
remain visible as records).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Mapping
from pathlib import Path

from core.logging import get_logger
from core.security import mac_key

logger = get_logger(__name__)

_KEY_LEN = 32

#: Key under which the token is stored inside the stamped record.
TRAIL_PROVENANCE_KEY = "trail_provenance"

_RECORD_KIND = "verified-outcome-record"

_warned_paths: set[str] = set()


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "outcome-trail-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug(
            "outcome-trail provenance: suspect key %s (%s)", path, reason)
        return
    _warned_paths.add(key)
    logger.warning(
        "outcome-trail provenance: refusing key %s — %s. Run-local "
        "verified-outcome records will not mint or verify (the reader "
        "demotes them to inconclusive) until this is fixed: %s",
        path, reason, remedy,
    )


def _read_existing_key(path: Path) -> bytes | mac_key.Refused | None:
    """Read an EXISTING key with the shared fd-fstat discipline
    (:func:`core.security.mac_key.read_existing_key`)."""
    return mac_key.read_existing_key(
        path, key_len=_KEY_LEN, warn=_warn_once_suspect_key)


def _load_or_create_key() -> bytes | None:
    """Read the key, lazily creating it (0700 dir, 0600 file, O_EXCL)
    if absent — the shared hardened discipline in
    :func:`core.security.mac_key.load_or_create_key`. Returns None
    when a key file exists but is unusable — the suspect key is never
    used, never replaced."""
    return mac_key.load_or_create_key(
        _key_path(), key_len=_KEY_LEN, warn=_warn_once_suspect_key,
        read_existing=_read_existing_key)


def key_usable() -> bool:
    """Whether this install can mint/verify trail tokens at all."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def record_content_sha256(record: Mapping[str, object]) -> str:
    """SHA-256 over the canonical (key-sorted, compact) JSON of the
    record WITHOUT its provenance token — the exact content identity
    the token authenticates (same construction as
    ``manifest_content_sha256`` in core/witness/provenance)."""
    from core.json import dumps_canonical
    body = {str(k): record[k] for k in record if k != TRAIL_PROVENANCE_KEY}
    try:
        text = dumps_canonical(body)
    except (TypeError, ValueError):
        # Non-JSON-safe content can never match a writer-side hash
        # (writers serialise the record, so theirs was JSON-safe).
        return "<unhashable>"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(fields: Mapping[str, object]) -> bytes:
    """Injective canonical encoding — key-sorted, length-prefixed —
    identical construction to witness provenance's."""
    items = sorted((str(k), str(v)) for k, v in fields.items())
    out = bytearray()
    out += len(items).to_bytes(4, "big")
    for key, value in items:
        for part in (key.encode("utf-8"), value.encode("utf-8")):
            out += len(part).to_bytes(4, "big")
            out += part
    return bytes(out)


def _mint(fields: Mapping[str, object]) -> str | None:
    """Hex HMAC-SHA256 token over *fields*, or None when no usable key
    is available. Writers treat None as "persist unstamped" — the
    reader then demotes the record."""
    try:
        key = _load_or_create_key()
    except OSError:
        return None
    if not key:
        return None
    return hmac.new(key, _canonical(fields), hashlib.sha256).hexdigest()


def _verify(fields: Mapping[str, object], token: object) -> bool:
    """Whether *token* is a valid MAC over *fields* under this
    install's key. Constant-time; never raises — any failure is the
    caller's demote path."""
    if not token or not isinstance(token, str):
        return False
    try:
        expected = _mint(fields)
        if expected is None:
            return False
        return hmac.compare_digest(expected, token.strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def _record_fields(content_sha256: str) -> dict[str, str]:
    return {"kind": _RECORD_KIND, "record_sha256": content_sha256}


def stamp_outcome_record(record: dict) -> None:
    """Stamp a ``VerifiedOutcome.to_dict()`` record a producer is about
    to append to the run-local trail. No usable key → the record stays
    unstamped and the reader demotes it to inconclusive."""
    token = _mint(_record_fields(record_content_sha256(record)))
    if token:
        record[TRAIL_PROVENANCE_KEY] = token


def verify_outcome_record(record: Mapping[str, object]) -> bool:
    """Whether *record* was written by a trail producer of THIS
    install. False for unstamped (legacy / foreign / attacker-staged)
    records and on any verification failure — the caller's demote
    path, never an error."""
    if not isinstance(record, Mapping):
        return False
    token = record.get(TRAIL_PROVENANCE_KEY)
    if not token:
        return False
    return _verify(
        _record_fields(record_content_sha256(record)), token)


__all__ = [
    "TRAIL_PROVENANCE_KEY",
    "key_usable",
    "record_content_sha256",
    "stamp_outcome_record",
    "verify_outcome_record",
]
