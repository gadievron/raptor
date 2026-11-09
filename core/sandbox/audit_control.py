"""Audit control-plane accounting shared by summary writers and readers.

Control records describe collection, not enforcement decisions. Retain bounded
aggregate diagnostics separately, with conservative loss flags and a digest
that joins the denial summary's existing provenance token. Record type names
are the producer protocol, not a heuristic prefix match.
"""

import hashlib
from typing import TypedDict, cast

from core.json import dumps_canonical


AUDIT_CONTROL_TYPES = frozenset({
    "audit_summary", "pid_budget_exceeded", "category_budget_exceeded",
    "category_budget_exceeded_sampling", "sampling_budget_exceeded",
    "global_budget_exceeded", "credential_keep_cap_exceeded",
    "parse_ambiguous_cap_exceeded",
})
_DROP_MARKERS = frozenset({
    "pid_budget_exceeded", "category_budget_exceeded", "sampling_budget_exceeded",
})
_POSITIVE_STATUS = ("reader_drained", "producer_reaped", "lineage_stopped", "stdout_closed")
_NEGATIVE_STATUS = ("reader_failed", "lineage_failed")
_LOSS_COUNTERS = ("append_failures", "parse_ambiguous_records_dropped")
_CAPTURE_FIELDS = frozenset({
    "version", "records", "summaries", "by_type", "capture_incomplete",
    "budget_truncated", "dropped_by_category", "malformed_records",
})


def capture_loss_status(record: dict) -> tuple[bool, bool]:
    """Return (known loss/unconfirmed completion, malformed status).

    Omitted fields retain compatibility with older writers. Present fields
    have exact boolean or nonnegative-integer shape; truthiness is not proof.
    """
    incomplete = malformed = False
    for name in (*_POSITIVE_STATUS, *_NEGATIVE_STATUS):
        if name not in record:
            continue
        value = record[name]
        if type(value) is not bool:
            malformed = incomplete = True
        elif ((name in _POSITIVE_STATUS and not value)
              or (name in _NEGATIVE_STATUS and value)):
            incomplete = True
    for name in _LOSS_COUNTERS:
        if name not in record:
            continue
        value = record[name]
        if type(value) is not int or value < 0:
            malformed = incomplete = True
        elif value:
            incomplete = True
    if "sampled_keeps" in record:
        kept = record["sampled_keeps"]
        if type(kept) is not int or kept < 0:
            malformed = incomplete = True
        elif kept and "dropped_by_category" not in record:
            # Retained samples do not establish loss. Without the producer's
            # drop accounting, however, complete absence remains unconfirmed.
            incomplete = True
    return incomplete, malformed


class _AuditCapture(TypedDict):
    version: int
    records: int
    summaries: int
    by_type: dict[str, int]
    capture_incomplete: bool
    budget_truncated: bool
    dropped_by_category: dict[str, int]
    malformed_records: int


def partition_audit_records(records: list[dict]) -> tuple[list[dict], dict | None]:
    """Keep event order/identity, aggregate control records without raw text.

    Drop counters are summed as reported by each summary record. A later
    clean record cannot erase earlier loss. Global-cap and sampling-mode
    notices alone do not establish actual drops. An unfinished control
    sequence is unconfirmed capture, including marker-only streams.
    """
    events: list[dict] | None = None
    capture: _AuditCapture = {
        "version": 1, "records": 0, "summaries": 0, "by_type": {},
        "capture_incomplete": False, "budget_truncated": False,
        "dropped_by_category": {}, "malformed_records": 0,
    }
    last_control = None
    for index, record in enumerate(records):
        kind = record.get("type")
        if not isinstance(kind, str) or kind not in AUDIT_CONTROL_TYPES:
            if events is not None:
                events.append(record)
            continue
        if events is None:
            events = records[:index]
        last_control = kind
        capture["records"] += 1
        counts = capture["by_type"]
        counts[kind] = counts.get(kind, 0) + 1
        if kind in _DROP_MARKERS:
            capture["budget_truncated"] = True
        if kind == "parse_ambiguous_cap_exceeded":
            capture["capture_incomplete"] = True
        if kind != "audit_summary":
            continue
        capture["summaries"] += 1
        incomplete, malformed = capture_loss_status(record)
        capture["capture_incomplete"] |= incomplete
        dropped = record.get("dropped_by_category", {})
        if not isinstance(dropped, dict):
            malformed = True
        else:
            for category, count in dropped.items():
                if not isinstance(category, str) or type(count) is not int or count < 0:
                    malformed = True
                    continue
                if count:
                    capture["budget_truncated"] = True
                    totals = capture["dropped_by_category"]
                    totals[category] = totals.get(category, 0) + count
        if malformed:
            capture["malformed_records"] += 1
            capture["capture_incomplete"] = True
    if last_control is None:
        return records, None
    if last_control != "audit_summary":
        capture["capture_incomplete"] = True
    # TypedDict describes the builder; the existing API returns this same
    # ordinary dictionary without copying its counters or changing identity.
    # A recognised control creates events before setting last_control.
    return cast(list[dict], events), cast(dict[str, object], capture)


def valid_audit_capture(capture: object) -> bool:
    """Validate the aggregate before it can drive reporting or MAC fields."""
    if not isinstance(capture, dict) or set(capture) != _CAPTURE_FIELDS:
        return False
    if type(capture["version"]) is not int or capture["version"] != 1:
        return False
    if any(type(capture[key]) is not int or capture[key] < 0
           for key in ("records", "summaries", "malformed_records")):
        return False
    if not capture["records"] or capture["malformed_records"] > capture["summaries"]:
        return False
    if any(type(capture[key]) is not bool
           for key in ("capture_incomplete", "budget_truncated")):
        return False
    counts = capture["by_type"]
    if (not isinstance(counts, dict) or not counts
            or any(key not in AUDIT_CONTROL_TYPES or type(value) is not int or value <= 0
                   for key, value in counts.items())
            or sum(counts.values()) != capture["records"]
            or counts.get("audit_summary", 0) != capture["summaries"]):
        return False
    dropped = capture["dropped_by_category"]
    if (not isinstance(dropped, dict)
            or any(not isinstance(key, str) or type(value) is not int or value <= 0
                   for key, value in dropped.items())):
        return False
    if ((capture["malformed_records"] or not capture["summaries"]
         or "parse_ambiguous_cap_exceeded" in counts)
            and not capture["capture_incomplete"]):
        return False
    if (dropped or any(key in _DROP_MARKERS for key in counts)) and not capture["budget_truncated"]:
        return False
    return True


def audit_capture_digest(capture: dict) -> str:
    """Canonical content binding; callers validate/construct the shape first."""
    return hashlib.sha256(dumps_canonical(capture).encode("utf-8")).hexdigest()
