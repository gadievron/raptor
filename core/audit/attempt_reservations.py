"""Run-bound recovery of admitted model attempts and unresolved usage.

Reservations are admission holds, not billed spend. Only an authenticated,
identified usage transition releases a hold into reported usage. The existing
audit trail supplies bounded reads and install/run-bound authentication; it
does not establish protection against rollback of an entire genuine trail.
"""
from __future__ import annotations

from copy import deepcopy
import json
import math
import os
from pathlib import Path
from threading import RLock
from typing import Any

from core.atomic_fs import open_hardened_read
from core.coverage import journal_mac
from core.json.bounded import loads_bounded
from core.json.jsonl import _append_jsonl_bytes
from core.run.metadata import load_run_metadata
from core.run.report_identity import valid_identity
from core.run.resume import persist_spend_floor

from . import record


_ACTION = "llm_attempt_accounting"
_IDENTITY_KEYS = ("run_id", "pass_id", "attempt_id")
_ATTEMPT_KEYS = ("call_id", "attempt_id", "work_id", "call_class", "provider", "model")


def _amount(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("invalid_attempt_amount")
    try:
        result = float(value)
    except OverflowError as error:
        raise ValueError("invalid_attempt_amount") from error
    if not math.isfinite(result) or result < 0:
        raise ValueError("invalid_attempt_amount")
    return result


def _tokens(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("invalid_attempt_tokens")
    return value


def _receipt(cost, tokens_in, tokens_out, tokens_total=None):
    tin, tout = _tokens(tokens_in), _tokens(tokens_out)
    total = tin + tout if tokens_total is None else _tokens(tokens_total)
    if total < tin + tout:
        raise ValueError("invalid_attempt_token_total")
    return {"cost_usd": _amount(cost), "tokens_in": tin,
            "tokens_out": tout, "tokens_total": total}


def _admission(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("invalid_attempt_admission")
    result: dict[str, Any] = {}
    for key in _ATTEMPT_KEYS:
        text = value.get(key)
        if not isinstance(text, str) or not text:
            raise ValueError("incomplete_attempt_identity")
        result[key] = text
    beneficiaries = value.get("beneficiaries", ())
    if (not isinstance(beneficiaries, (tuple, list))
            or any(not isinstance(item, str) or not item for item in beneficiaries)):
        raise ValueError("invalid_attempt_beneficiaries")
    result["beneficiaries"] = list(dict.fromkeys(beneficiaries))
    result["reservation_usd"] = _amount(value.get("reservation_usd"))
    return result


class AttemptReservations:
    """Authenticated attempt holds for one lifecycle attempt and directory.

    A resume retains the lifecycle identity while changing its segment. An
    explicit retry has a new identity and cannot adopt the prior holds.
    The caller must refuse dispatch if ``gap`` is present, and commit
    ``admit`` before contacting a provider. A false admission result denotes
    an existing attempt; it is not permission to dispatch that attempt again.
    """

    def __init__(self, out_dir: Path, *, resume: bool,
                 prior_known_usd: float = 0):
        self.out_dir = Path(out_dir).resolve()
        self.gap: str | None = None
        self.identity: dict[str, str] = {}
        self._lock = RLock()
        self._sequence = 0
        self._seen: dict[int, dict[str, Any]] = {}
        self._rows: dict[str, dict[str, Any]] = {}
        self._stages: dict[str, str] = {}
        self._baseline_known = 0.0
        self._binding = journal_mac.audit_log_run_binding(self.out_dir)
        try:
            metadata = load_run_metadata(self.out_dir)
            identity = metadata.get("reporting_identity") if isinstance(metadata, dict) else None
            if not valid_identity(identity):
                raise ValueError("missing_attempt_lifecycle_identity")
            self.identity = {key: identity[key] for key in _IDENTITY_KEYS}
            prior = _amount(prior_known_usd)
            self._load()
            if not self._sequence:
                if resume:
                    raise ValueError("missing_attempt_recovery_state")
                self._append("start", known_before_store=prior)
            elif prior > self.known_spend_usd:
                reported = sum(row.get("cost_usd", 0.0) for row in self._rows.values())
                self._append("carry", known_before_store=max(self._baseline_known, prior - reported))
        except (OSError, TypeError, ValueError) as error:
            self.gap = str(error) if isinstance(error, ValueError) else "unreadable_attempt_recovery_state"

    def _require_ready(self) -> None:
        if self.gap:
            raise ValueError(self.gap)

    def _load(self) -> None:
        rows, disclosure = record.load_audit_log_disclosed(self.out_dir)
        if not disclosure.complete:
            raise ValueError("incomplete_attempt_recovery_trail")
        # The tolerant reader can skip a malformed final record. Validate
        # physical lines before interpreting their absence as no hold.
        for path in record.audit_log_paths(self.out_dir):
            try:
                fd = open_hardened_read(path)
            except FileNotFoundError:
                continue
            with os.fdopen(fd, "rb") as stream:
                remaining = os.fstat(stream.fileno()).st_size
                if remaining > record._AUDIT_LOG_MAX_BYTES:
                    raise ValueError("incomplete_attempt_recovery_trail")
                count = 0
                while remaining:
                    line = stream.readline(min(remaining, record._AUDIT_LOG_MAX_LINE_BYTES + 1))
                    if not line or not line.endswith(b"\n"):
                        raise ValueError("truncated_attempt_recovery_trail")
                    remaining -= len(line)
                    if line.strip():
                        if not isinstance(loads_bounded(line, max_bytes=record._AUDIT_LOG_MAX_LINE_BYTES), dict):
                            raise ValueError("invalid_attempt_recovery_row")
                        count += 1
                        if count > record._AUDIT_LOG_MAX_ROWS_PER_SHARD:
                            raise ValueError("incomplete_attempt_recovery_trail")
        relevant = [row for row in rows if isinstance(row, dict) and row.get("action") == _ACTION]
        for row in relevant:
            if not journal_mac.verify_audit_log_row(
                    row, row.get(journal_mac.TOKEN_KEY), self._binding):
                raise ValueError("unverified_attempt_recovery_row")
        # Use the authority-bearing reader, not the unsigned telemetry trail.
        for row in record.load_verified_audit_log(self.out_dir):
            if row.get("action") != _ACTION or row.get("identity") != self.identity:
                continue
            self._apply({key: value for key, value in row.items()
                         if key != journal_mac.TOKEN_KEY})

    def _apply(self, row: dict[str, Any]) -> None:
        if row.get("schema_version") != 1 or type(row.get("schema_version")) is not int:
            raise ValueError("invalid_attempt_recovery_version")
        if row.get("run_binding") != self._binding or row.get("identity") != self.identity:
            raise ValueError("mismatched_attempt_recovery_identity")
        sequence = row.get("sequence")
        if type(sequence) is not int or sequence < 1:
            raise ValueError("invalid_attempt_recovery_sequence")
        if sequence in self._seen:
            if self._seen[sequence] != row:
                raise ValueError("conflicting_attempt_recovery_sequence")
            return
        if sequence != self._sequence + 1:
            raise ValueError("incomplete_attempt_recovery_sequence")
        stage = row.get("stage")
        if not self._sequence and stage != "start":
            raise ValueError("missing_attempt_recovery_start")
        if stage in {"start", "carry"}:
            if stage == "start" and sequence != 1:
                raise ValueError("duplicate_attempt_recovery_start")
            baseline = _amount(row.get("known_before_store"))
            if baseline < self._baseline_known:
                raise ValueError("decreasing_attempt_known_floor")
            if stage == "carry" and baseline > self._baseline_known:
                for item in self._rows.values():
                    if item["billing_state"] == "unknown":
                        item["prior_floor_overlap_unknown"] = True
            self._baseline_known = baseline
        else:
            admission = _admission(row.get("attempt"))
            attempt_id = admission["attempt_id"]
            previous = self._rows.get(attempt_id)
            if stage == "admitted":
                if previous is not None:
                    raise ValueError("duplicate_attempt_recovery_admission")
                self._rows[attempt_id] = {**admission, "billing_state": "unknown"}
            else:
                if previous is None or _admission(previous) != admission:
                    raise ValueError("mismatched_attempt_recovery_transition")
                if stage == "unknown":
                    if previous["billing_state"] == "reported":
                        raise ValueError("reported_attempt_became_unknown")
                elif stage == "reported":
                    receipt = _receipt(row.get("cost_usd"), row.get("tokens_in"),
                                       row.get("tokens_out"), row.get("tokens_total"))
                    if previous["billing_state"] == "reported":
                        if any(previous[key] != value for key, value in receipt.items()):
                            raise ValueError("conflicting_attempt_usage")
                    else:
                        total = self._baseline_known + sum(
                            item.get("cost_usd", 0.0) for item in self._rows.values()) + receipt["cost_usd"]
                        if not math.isfinite(total):
                            raise ValueError("invalid_attempt_total")
                        self._rows[attempt_id] = {**admission, **receipt, "billing_state": "reported"}
                else:
                    raise ValueError("invalid_attempt_recovery_stage")
            self._stages[attempt_id] = stage
        self._seen[sequence] = deepcopy(row)
        self._sequence = sequence

    def _append(self, stage: str, **fields: Any) -> None:
        self._require_ready()
        row = {"action": _ACTION, "schema_version": 1, "identity": self.identity,
               "run_binding": self._binding, "sequence": self._sequence + 1,
               "stage": stage, **fields}
        try:
            stamped = record.stamp_audit_log_row(row, self.out_dir)
            if not journal_mac.verify_audit_log_row(
                    stamped, stamped.get(journal_mac.TOKEN_KEY), self._binding):
                raise ValueError("unavailable_attempt_recovery_signature")
            encoded = json.dumps(stamped, allow_nan=False, separators=(",", ":")).encode("utf-8")
            if len(encoded) + 1 > record._AUDIT_LOG_MAX_LINE_BYTES:
                raise ValueError("oversize_attempt_recovery_row")
            # Commit the exact checked token, without a second optional mint.
            _append_jsonl_bytes(record.audit_log_append_path(self.out_dir), encoded + b"\n", mode=0o600)
            self._apply(row)
        except (OSError, TypeError, ValueError) as error:
            self.gap = str(error) if isinstance(error, ValueError) else "attempt_recovery_write_failed"
            raise ValueError(self.gap) from error

    def pending(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy([row for row in self._rows.values() if row["billing_state"] == "unknown"])

    def reported(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy([row for row in self._rows.values() if row["billing_state"] == "reported"])

    @property
    def known_spend_usd(self) -> float:
        with self._lock:
            return self._baseline_known + sum(row.get("cost_usd", 0.0) for row in self._rows.values())

    def admit(self, row: dict[str, Any]) -> bool:
        with self._lock:
            self._require_ready()
            admission = _admission(row)
            previous = self._rows.get(admission["attempt_id"])
            if previous is not None:
                if _admission(previous) != admission:
                    self.gap = "conflicting_attempt_admission"
                    raise ValueError(self.gap)
                return False
            self._append("admitted", attempt=admission)
            return True

    def finish(self, attempt_id: str, *, cost_usd: float | None,
               tokens_in: int = 0, tokens_out: int = 0,
               tokens_total: int | None = None) -> bool:
        with self._lock:
            self._require_ready()
            previous = self._rows.get(attempt_id)
            if previous is None:
                self.gap = "unknown_attempt_transition"
                raise ValueError(self.gap)
            if cost_usd is None:
                if previous["billing_state"] == "reported" or self._stages[attempt_id] == "unknown":
                    return False
                self._append("unknown", attempt=_admission(previous))
                return True
            receipt = _receipt(cost_usd, tokens_in, tokens_out, tokens_total)
            if previous.get("prior_floor_overlap_unknown") and receipt["cost_usd"] > 0:
                raise ValueError("ambiguous_prior_floor_usage")
            if previous["billing_state"] == "reported":
                if any(previous[key] != value for key, value in receipt.items()):
                    self.gap = "conflicting_attempt_usage"
                    raise ValueError(self.gap)
                return False
            self._append("reported", attempt=_admission(previous), **receipt)
            try:
                persist_spend_floor(self.out_dir, self.known_spend_usd)
            except (OSError, TypeError, ValueError):
                # The signed attempt transition remains recoverable even if
                # the separate best-effort known-spend floor cannot advance.
                pass
            return True
