"""Read-only processing disclosure over saved knowledge provenance.

These counts do not authenticate evidence, adjudicate claims or certify that
an answer was understood. Assessment publication remains domain-owned.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from core.json import load_json

_ROLE = "context_provenance_not_verification_evidence"
_MAX_BYTES = 8 * 1024 * 1024


def _ids(value: object) -> set[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item or len(item) > 128 for item in value
    ):
        raise ValueError("invalid knowledge identifiers")
    return set(value)


def _rows(value: object) -> list[dict]:
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("invalid knowledge records")
    return value


def load_knowledge_processing(out_dir: Path) -> dict | None:
    """Distinguish legacy absence from an unavailable present record."""
    path = out_dir / "knowledge-results.json"
    if not path.exists() and not path.is_symlink():
        return None
    unavailable = {"state": "unavailable", "artifact": path.name}
    data = load_json(path, max_bytes=_MAX_BYTES)
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1 or data.get("role") != _ROLE):
        return unavailable
    try:
        groups = [_rows(data.get("requests")), _rows(data.get("caller_context_requests"))]
        events, units = _rows(data.get("events")), _rows(data.get("units"))
        states = {}
        for rows in groups:
            for row in rows:
                if not isinstance(row, dict):
                    return unavailable
                request_id = row.get("request_id")
                _ids([request_id])
                processing = row.get("processing")
                state = processing.get("state") if isinstance(processing, dict) else None
                if not isinstance(state, str) or not state or len(state) > 80 or request_id in states:
                    return unavailable
                states[request_id] = state
        delivered = set()
        for event in events:
            if not isinstance(event, dict):
                return unavailable
            if event.get("event") == "continuation_completed":
                if not isinstance(event.get("pass_id"), str) or not event["pass_id"]:
                    return unavailable
                delivered.update(_ids(event.get("delivered_request_ids")))
        pending, delta = set(), set()
        active = 0
        for unit in units:
            cycle = unit.get("cycle") if isinstance(unit, dict) else None
            if not isinstance(cycle, dict):
                return unavailable
            pending.update(_ids(cycle.get("pending_ids")))
            delta.update(_ids(cycle.get("delta_ids")))
            pass_id = cycle.get("active_pass_id")
            if pass_id is not None and (not isinstance(pass_id, str) or not pass_id):
                return unavailable
            active += pass_id is not None
        known = set(states)
        if not (delivered | pending | delta) <= known:
            return unavailable
        counts = Counter(states.values())
        return {"state": "recorded", "artifact": path.name, "requests": len(states),
                "delivered_requests": len(delivered),
                "available_requests_never_delivered": sum(state == "context_available" and key not in delivered
                                                          for key, state in states.items()),
                "unavailable_requests": counts["unavailable"],
                "deferred_requests": counts["deferred"],
                "pending_requests": len(pending), "pending_delivery_requests": len(delta),
                "active_passes": active}
    except (ValueError, TypeError):
        return unavailable


def knowledge_processing_lines(report: dict) -> list[str]:
    """Render only bounded counts, never raw questions, answers or prompts."""
    record = report.get("knowledge_processing")
    if not isinstance(record, dict):
        return []
    if record.get("state") != "recorded":
        return ["Knowledge processing record unavailable; request completion and delivery are unknown."]
    return [
        f"Knowledge processing: {record['requests']} recorded requests; "
        f"{record['delivered_requests']} recorded as delivered to completed continuations; "
        f"{record['available_requests_never_delivered']} available requests with no recorded completed delivery.",
        f"Knowledge limitations: {record['unavailable_requests']} unavailable, "
        f"{record['deferred_requests']} deferred; {record['pending_requests']} pending requests, "
        f"{record['pending_delivery_requests']} pending delivery updates, "
        f"{record['active_passes']} in-flight continuations.",
        "Knowledge processing is context provenance, not verification evidence or proof of safety. "
        "Delivery totals are historical: newer updates may remain pending for the same request. "
        "Recorded delivery describes supplied context, not verified comprehension. "
        "See knowledge-results.json for recorded request and pass identities.",
    ]
