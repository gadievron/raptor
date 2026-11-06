"""End-of-run egress summary derived from proxy-events.jsonl.

Aggregates proxy connection events by host and result, writes a
machine-readable ``egress-summary.json`` alongside the run output, and
emits a one-line INFO log so operators get immediate egress visibility
without reading the raw event log.

Best-effort: any failure is swallowed — the summary is a convenience
artefact, not a trust boundary (triage owns that).
"""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path
from typing import Any

from core.sandbox.proxy import PROXY_EVENTS_FILENAME
from core.sandbox.evidence import _unique_evidence_object
from core.security.capped_read import read_capped
from core.security.log_sanitisation import sanitise_for_terminal

EGRESS_SUMMARY_FILE = "egress-summary.json"

_MAX_LINES = 200_000
_MAX_INPUT_BYTES = 64 * 1024 * 1024
_MAX_LINE_CHARS = 1 * 1024 * 1024

_CONTROL_PLANE_RESULTS = frozenset({"buffer_overflow", "parser_jail_degraded"})

_DENIED_PREFIXES = ("denied_", "would_deny_")

_FAILED_RESULTS = frozenset({
    "dns_failed", "upstream_failed", "timed_out",
    "bad_request", "handler_error", "refused_capacity", "parser_unavailable",
})

log = logging.getLogger(__name__)


def _read_proxy_events(
    run_dir: Path, *, issues: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Read bounded JSONL and retain loss reasons; does not verify MACs."""
    if issues is None:
        issues = set()
    data = read_capped(run_dir / PROXY_EVENTS_FILENAME, _MAX_INPUT_BYTES)
    if data is None:
        return []
    events: list[dict[str, Any]] = []
    # Preserve universal newlines while deferring UTF-8 validation to each
    # record. Strict decoding in TextIOWrapper can discard valid neighbors
    # in the same buffer; replacement decoding would invent event content.
    # The input cap bounds even a single long line; the character cap keeps
    # oversized records out of the JSON decoder.
    with io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="surrogateescape") as fh:
        for i, line in enumerate(fh):
            if i >= _MAX_LINES:
                issues.add("line_limit")
                break
            if len(line) > _MAX_LINE_CHARS:
                issues.add("oversized_record")
                continue
            line = line.strip()
            if not line:
                continue
            try:
                # Invalid source bytes survived only as surrogate escapes.
                # Reject them before parsing, without altering valid Unicode.
                line.encode("utf-8")
                obj = json.loads(line, object_pairs_hook=_unique_evidence_object)
                if isinstance(obj, dict):
                    events.append(obj)
                else:
                    issues.add("nonobject_record")
            except (ValueError, RecursionError):
                issues.add("malformed_record")
                continue
    return events


def _valid_proxy_event(event: dict[str, Any]) -> bool:
    """Keep malformed fields from invalidating the rest of the summary."""
    result = event.get("result")
    if not isinstance(result, str) or not result:
        return False
    host = event.get("host")
    if host is not None and not isinstance(host, str):
        return False
    port = event.get("port")
    # Refused requests may report an out-of-range integer port; retain
    # that diagnostic rather than enforcing CONNECT policy here.
    if port is not None and type(port) is not int:
        return False
    for field in ("bytes_u2c", "bytes_c2u"):
        count = event.get(field)
        if count is not None and (type(count) is not int or count < 0):
            return False
    return True


def summarise_egress(run_dir: Path) -> dict[str, Any] | None:
    """Aggregate usable events, with optional known-input-loss metadata.

    Returns None when no connection events are usable. Partial results add
    input_incomplete/input_issues; absence of these fields is not provenance
    verification or proof that the producer captured every connection.
    """
    issues: set[str] = set()
    raw_events = _read_proxy_events(run_dir, issues=issues)
    if not raw_events:
        return None

    events = []
    for event in raw_events:
        if not _valid_proxy_event(event):
            issues.add("malformed_fields")
            continue
        if event["result"] == "buffer_overflow":
            issues.add("producer_overflow")
        if event["result"] not in _CONTROL_PLANE_RESULTS:
            events.append(event)
    if not events:
        return None

    by_host: dict[tuple[str | None, int | None], dict[str, Any]] = {}
    # Keep display order in reasons while avoiding repeated linear scans.
    reasons_seen: dict[tuple[str | None, int | None], set[str]] = {}
    total_allowed = 0
    total_denied = 0
    total_failed = 0
    total_bytes_in = 0
    total_bytes_out = 0

    for ev in events:
        result = ev.get("result")
        # Establish identity before formatting an absent host for display.
        raw_host = ev.get("host") or None
        host = raw_host if raw_host is not None else "<unknown>"
        port = ev.get("port")
        key = (raw_host, port)

        if key not in by_host:
            reasons_seen[key] = set()
            by_host[key] = {
                "host": host,
                "port": port,
                "allowed": 0,
                "denied": 0,
                "failed": 0,
                "bytes_in": 0,
                "bytes_out": 0,
                "reasons": [],
            }

        entry = by_host[key]
        b_in = ev.get("bytes_u2c", 0) or 0
        b_out = ev.get("bytes_c2u", 0) or 0

        if result == "allowed":
            entry["allowed"] += 1
            total_allowed += 1
        elif result and result.startswith(_DENIED_PREFIXES):
            entry["denied"] += 1
            total_denied += 1
            if result not in reasons_seen[key]:
                reasons_seen[key].add(result)
                entry["reasons"].append(result)
        elif result in _FAILED_RESULTS:
            entry["failed"] += 1
            total_failed += 1
            if result not in reasons_seen[key]:
                reasons_seen[key].add(result)
                entry["reasons"].append(result)
        else:
            entry["failed"] += 1
            total_failed += 1

        entry["bytes_in"] += b_in
        entry["bytes_out"] += b_out
        total_bytes_in += b_in
        total_bytes_out += b_out

    unique_hosts = {host for host, _port in by_host if host is not None}

    total = total_allowed + total_denied + total_failed
    summary = {
        "total_connections": total,
        "allowed": total_allowed,
        "denied": total_denied,
        "failed": total_failed,
        "unique_hosts": len(unique_hosts),
        "total_bytes_in": total_bytes_in,
        "total_bytes_out": total_bytes_out,
        "hosts": sorted(by_host.values(), key=lambda e: e["host"]),
    }
    if issues:
        summary["input_incomplete"] = True
        summary["input_issues"] = sorted(issues)
    return summary


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    unit, suffix = (1024, "KiB") if n < 1024 * 1024 else (1024 * 1024, "MiB")
    # Round to one decimal with ties to even, without converting counts
    # to float: valid JSON integers may exceed the float range.
    tenths, remainder = divmod(n * 10, unit)
    if remainder * 2 > unit or (remainder * 2 == unit and tenths % 2):
        tenths += 1
    return f"{tenths // 10}.{tenths % 10} {suffix}"


def finalize_egress_summary(output_dir: Path) -> dict[str, Any] | None:
    """Summarise, persist, and log egress activity for a completed run.

    Called from ``complete_run`` (and the fail/cancel paths) in
    ``core.run.metadata``.  Best-effort: never raises.
    """
    output_dir = Path(output_dir)
    try:
        summary = summarise_egress(output_dir)
        if summary is None:
            return None

        from core.atomic_fs import write_text_atomically
        out_path = output_dir / EGRESS_SUMMARY_FILE
        write_text_atomically(
            out_path,
            json.dumps(summary, indent=2, default=str) + "\n",
        )

        if summary.get("input_incomplete"):
            log.warning(
                "egress summary uses partial input (%s); "
                "counts cover accepted records only",
                ", ".join(summary["input_issues"]),
            )

        denied = summary["denied"]
        failed = summary["failed"]
        non_ok = denied + failed
        hosts = summary["unique_hosts"]
        bytes_in = _format_bytes(summary["total_bytes_in"])
        bytes_out = _format_bytes(summary["total_bytes_out"])
        total = summary["total_connections"]

        if non_ok == 0:
            log.info(
                "egress: %d connection(s) to %d host(s), %s in / %s out"
                " → %s",
                total, hosts, bytes_in, bytes_out, sanitise_for_terminal(str(out_path)),
            )
        else:
            parts = []
            if denied:
                parts.append(f"{denied} denied")
            if failed:
                parts.append(f"{failed} failed")
            log.info(
                "egress: %d connection(s) to %d host(s) (%s),"
                " %s in / %s out → %s",
                total, hosts, ", ".join(parts),
                bytes_in, bytes_out, sanitise_for_terminal(str(out_path)),
            )
        return summary
    except Exception as exc:  # noqa: BLE001 — never fail lifecycle
        # A raw traceback can reintroduce path/error control bytes after
        # sanitizing the message. Retain bounded exception context instead.
        log.debug(
            "finalize_egress_summary failed for %s: %s: %s",
            sanitise_for_terminal(str(output_dir)), type(exc).__name__,
            sanitise_for_terminal(str(exc)),
        )
        return None
