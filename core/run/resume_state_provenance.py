"""Authorship tokens for resume-state fields read back from run dirs.

Run output directories are writable by less-trusted code (sandboxed
children, the scanned target's own build steps), so resume-time reads
of ``.raptor-run.json`` / the pinned run config must not take
load-bearing fields at face value. Two resume-state surfaces are
stamped here at write time with an HMAC-SHA256 token under one shared
per-purpose key:

* the **worker-liveness record** (``tool_pid`` + ``tool_pid_start`` in
  the run metadata) — the resume double-drive guard's evidence. A
  planted long-lived pid read as trusted blocked resume forever; a
  planted self-pid rode the guard's own-process exemption.
* the **persisted cost cap** (``max_cost_usd`` in a pipeline's pinned
  run config) — a rewritten cap (``0``/huge) silently lifted the
  operator's budget on resume.

Both are resume-state integrity records with the same writer (the run
owner) and the same reader (the resume path), so they deliberately
share ONE key file — ``$XDG_DATA_HOME/raptor/resume-state-mac.key`` —
distinct per-``kind`` fields keep the two token spaces from cross-
verifying. The key is never shared with any OTHER subsystem's key file
(:mod:`core.security.mac_key` doctrine) and lives outside every
LLM-writable and sandbox-readable tree. A verified token proves the
record was minted by code that could read that key file, nothing
stronger; key confidentiality is the trust anchor.

Binding doctrine differs per record:

* Worker records carry NO run binding — the (pid, starttime) tuple is
  already a transient machine-local fact (replaying it to another run
  dir only "claims" a worker that is live anyway, a transient state),
  and run binding would break legitimate run-dir moves (``/project
  adopt``).
* Cost-cap records bind to the ABSOLUTE run dir — a stamped "uncapped"
  config copied into another run would lift that run's budget, a
  durable grant. A moved run dir therefore verifies as unstamped and
  resumes under the reader's conservative default (``--max-cost`` on
  the resume invocation is the documented remedy).

Failure policy is demote-never-error: no usable key → the state
persists unstamped, and readers degrade exactly as they do for legacy
pre-stamp records (liveness demotes to unverified-never-blocks; the
cost cap clamps to the conservative default). An unverified record
must never satisfy a trust-granting branch (the resume guard's
self-pid exemption, the legacy uncapped-cap mapping).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from core.logging import get_logger
from core.security import mac_key

logger = get_logger(__name__)

_KEY_LEN = 32

#: Metadata key under which the worker-record token is stored.
WORKER_PROVENANCE_KEY = "tool_pid_provenance"

#: Run-config key under which the cost-cap token is stored.
COST_CAP_PROVENANCE_KEY = "max_cost_usd_provenance"

_WORKER_KIND = "run-worker-liveness"
_COST_CAP_KIND = "audit-resume-cost-cap"

_warned_paths: set[str] = set()


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "resume-state-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug(
            "resume-state provenance: suspect key %s (%s)", path, reason)
        return
    _warned_paths.add(key)
    logger.warning(
        "resume-state provenance: refusing key %s — %s. Resume-state "
        "records (worker liveness, persisted cost caps) will not mint "
        "or verify (readers degrade them to the unverified posture: "
        "liveness never blocks resume, cost caps clamp to the "
        "conservative default) until this is fixed: %s",
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
    """Whether this install can mint/verify resume-state tokens at all."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def _canonical(fields: Mapping[str, object]) -> bytes:
    """Injective canonical encoding — key-sorted, length-prefixed —
    identical construction to witness/outcome-trail provenance's."""
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
    is available. Writers treat None as "persist unstamped" — readers
    then apply their unverified degrade."""
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
    caller's degrade path."""
    if not token or not isinstance(token, str):
        return False
    try:
        expected = _mint(fields)
        if expected is None:
            return False
        return hmac.compare_digest(expected, token.strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the degrade path, never an error
        return False


# ── Worker-liveness records (run metadata) ───────────────────────────

def _worker_fields(record: Mapping[str, Any]) -> dict[str, str]:
    # str() over the recorded values: the canonical encoding is over
    # strings, and a verify against on-disk JSON must reproduce the
    # mint-side encoding byte for byte (ints round-trip through JSON;
    # a tampered type lands on a different string and fails closed).
    return {
        "kind": _WORKER_KIND,
        "tool_pid": str(record.get("tool_pid", "")),
        "tool_pid_start": str(record.get("tool_pid_start", "")),
    }


def stamp_worker_record(record: dict[str, Any]) -> None:
    """Stamp a metadata dict carrying ``tool_pid`` (and optionally
    ``tool_pid_start``) at write time. A record WITHOUT a worker pid —
    or one minted with no usable key — ends up with no token: readers
    treat it as unverified (liveness never blocks, never trusted as
    self)."""
    record.pop(WORKER_PROVENANCE_KEY, None)
    if record.get("tool_pid") is None:
        return
    token = _mint(_worker_fields(record))
    if token:
        record[WORKER_PROVENANCE_KEY] = token


def verify_worker_record(record: Mapping[str, Any]) -> bool:
    """Whether *record*'s ``tool_pid``/``tool_pid_start`` pair was
    stamped by THIS install. False for unstamped (legacy / foreign /
    attacker-staged) records and on any verification failure — the
    caller's degrade path, never an error."""
    if not isinstance(record, Mapping):
        return False
    token = record.get(WORKER_PROVENANCE_KEY)
    if not token:
        return False
    return _verify(_worker_fields(record), token)


# ── Persisted cost caps (pinned run configs) ─────────────────────────

def _cap_canonical(value: object) -> str:
    """Injective string form of a persisted cap value. ``repr(float)``
    round-trips exactly, so the verify side reproduces the mint side
    from the JSON-decoded value; non-numeric shapes encode their type
    and repr so distinct values can never share a canonical. A single
    shared sentinel would be a forgery seam: the resume reader coerces
    via ``float()``, which accepts numeric STRINGS, so a stamp minted
    over ``"5"`` must not verify for ``"999999"`` (no current writer
    persists strings — this pins the property against future ones)."""
    if value is None:
        return "none"
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return f"<non-numeric:{type(value).__name__}:{value!r}>"
    try:
        return repr(float(value))
    except OverflowError:
        return "<non-finite>"


def _cost_cap_fields(value: object, out_dir: Path) -> dict[str, str]:
    return {
        "kind": _COST_CAP_KIND,
        "max_cost_usd": _cap_canonical(value),
        "run_dir": str(Path(out_dir).resolve()),
    }


def stamp_cost_cap(config: dict[str, Any], out_dir: Path) -> None:
    """Stamp a run config's ``max_cost_usd`` (including an uncapped
    ``None`` — deleting the stamped key must not verify as a legacy
    uncapped run) before it is persisted under *out_dir*. No usable
    key → the config persists unstamped and resume applies the
    conservative-default clamp."""
    config.pop(COST_CAP_PROVENANCE_KEY, None)
    token = _mint(_cost_cap_fields(config.get("max_cost_usd"), out_dir))
    if token:
        config[COST_CAP_PROVENANCE_KEY] = token


def verify_cost_cap(config: Mapping[str, Any], out_dir: Path) -> bool:
    """Whether *config*'s ``max_cost_usd`` was stamped for THIS run dir
    by THIS install. False for unstamped (legacy / foreign / tampered)
    configs and on any verification failure — the caller's clamp path,
    never an error."""
    if not isinstance(config, Mapping):
        return False
    token = config.get(COST_CAP_PROVENANCE_KEY)
    if not token:
        return False
    return _verify(
        _cost_cap_fields(config.get("max_cost_usd"), out_dir), token)


__all__ = [
    "COST_CAP_PROVENANCE_KEY",
    "WORKER_PROVENANCE_KEY",
    "key_usable",
    "stamp_cost_cap",
    "stamp_worker_record",
    "verify_cost_cap",
    "verify_worker_record",
]
