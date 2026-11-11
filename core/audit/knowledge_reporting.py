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


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError("invalid knowledge identifiers")
    return value


def _ids(value: object) -> set[str]:
    if not isinstance(value, list):
        raise ValueError("invalid knowledge identifiers")
    return {_identifier(item) for item in value}


def _rows(value: object) -> list[dict]:
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("invalid knowledge records")
    return value


def _unit(value: object) -> tuple[str, str, int]:
    if isinstance(value, dict):
        parts = [value.get(key) for key in ("file", "function", "line_start")]
    elif isinstance(value, list) and len(value) == 3:
        parts = value
    else:
        raise ValueError("invalid knowledge unit")
    file, function, line = parts
    if (not isinstance(file, str) or not file or len(file) > 4096
            or not isinstance(function, str) or not function or len(function) > 512
            or type(line) is not int or line < 0):
        raise ValueError("invalid knowledge unit")
    return file, function, line


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
        contexts: set[tuple[tuple[str, str, int], str]] = set()
        passes: dict[str, tuple[str, str, int]] = {}
        receipts: set[tuple[str, str]] = set()
        for event in events:
            if event.get("event") == "context_delta_offered":
                context_id = _identifier(event.get("context_id"))
                kind, version = event.get("kind"), event.get("version")
                if (not isinstance(kind, str) or not kind or not isinstance(version, str)
                        or not version or context_id != f"context:{kind}:{version}"):
                    return unavailable
                contexts.add((_unit(event.get("origin")), context_id))
            elif event.get("event") == "continuation_reserved":
                pass_id = _identifier(event.get("pass_id"))
                event_unit = _unit(event.get("origin"))
                if pass_id in passes and passes[pass_id] != event_unit:
                    return unavailable
                passes[pass_id] = event_unit
            elif event.get("event") == "review_prompt_context":
                pass_id = _identifier(event.get("pass_id"))
                for row in _rows(event.get("records")):
                    if row.get("field") == "external_context_delivery":
                        context_id = _identifier(row.get("context_id"))
                        if type(row.get("delivered")) is not bool:
                            return unavailable
                        if row["delivered"]:
                            receipts.add((pass_id, context_id))
        context_ids = {context_id for _, context_id in contexts}
        if context_ids & set(states):
            return unavailable
        delivered, delivered_contexts = set(), set()
        for event in events:
            if not isinstance(event, dict):
                return unavailable
            if event.get("event") == "continuation_completed":
                if not isinstance(event.get("pass_id"), str) or not event["pass_id"]:
                    return unavailable
                for item in _ids(event.get("delivered_request_ids")):
                    if item in states:
                        delivered.add(item)
                    elif (passes.get(event["pass_id"]), item) in contexts and (event["pass_id"], item) in receipts:
                        delivered_contexts.add((passes[event["pass_id"]], item))
                    else:
                        return unavailable
        pending: set[str] = set()
        delta: set[str] = set()
        context_delta: set[tuple[tuple[str, str, int], str]] = set()
        active = 0
        for unit in units:
            cycle = unit.get("cycle") if isinstance(unit, dict) else None
            if not isinstance(cycle, dict):
                return unavailable
            pending.update(_ids(cycle.get("pending_ids")))
            for item in _ids(cycle.get("delta_ids")):
                if item in states:
                    delta.add(item)
                elif (_unit(unit.get("unit")), item) in contexts:
                    context_delta.add((_unit(unit.get("unit")), item))
                else:
                    return unavailable
            active_pass_id = cycle.get("active_pass_id")
            if active_pass_id is not None and (not isinstance(active_pass_id, str) or not active_pass_id):
                return unavailable
            active += active_pass_id is not None
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
                "context_updates": len(contexts), "delivered_context_updates": len(delivered_contexts),
                "pending_delivery_context_updates": len(context_delta),
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
        f"Knowledge context updates: {record['context_updates']} offered unit/version records; "
        f"{record['delivered_context_updates']} recorded as fitted into completed continuations; "
        f"{record['pending_delivery_context_updates']} pending context updates.",
        "Knowledge processing is context provenance, not verification evidence or proof of safety. "
        "Delivery totals are historical: newer updates may remain pending for the same request. "
        "Recorded delivery describes supplied context, not verified comprehension. "
        "Prompt fitting does not establish provider acknowledgement or model use. "
        "See knowledge-results.json for recorded request and pass identities.",
    ]
