"""End-of-run egress summary derived from proxy-events.jsonl.

Aggregates proxy connection events by host and result, writes a
machine-readable ``egress-summary.json`` alongside the run output, and
emits a one-line INFO log so operators get immediate egress visibility
without reading the raw event log.

Best-effort: any failure is swallowed — the summary is a convenience
artefact, not a trust boundary (triage owns that).
"""

from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

from core.sandbox.proxy import PROXY_EVENTS_FILENAME

EGRESS_SUMMARY_FILE = "egress-summary.json"

_MAX_LINES = 200_000

_CONTROL_PLANE_RESULTS = frozenset({"buffer_overflow", "parser_jail_degraded"})

_DENIED_PREFIXES = ("denied_", "would_deny_")

_FAILED_RESULTS = frozenset({
    "dns_failed", "upstream_failed", "timed_out",
    "bad_request", "handler_error", "refused_capacity",
})

log = logging.getLogger(__name__)


def _read_proxy_events(run_dir: Path) -> list[dict[str, Any]]:
    """Minimal JSONL reader — no MAC verification (not a trust surface)."""
    path = run_dir / PROXY_EVENTS_FILENAME
    try:
        fd = os.open(
            str(path),
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return []
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as fh:
            fd = -1  # fdopen owns it now
            for i, line in enumerate(fh):
                if i >= _MAX_LINES:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        events.append(obj)
                except (json.JSONDecodeError, ValueError):
                    continue
    finally:
        if fd >= 0:
            os.close(fd)
    return events


def summarise_egress(run_dir: Path) -> dict[str, Any] | None:
    """Build the egress summary dict. Returns None if no events exist."""
    raw_events = _read_proxy_events(run_dir)
    if not raw_events:
        return None

    events = [e for e in raw_events
              if e.get("result") not in _CONTROL_PLANE_RESULTS]
    if not events:
        return None

    by_host: dict[str, dict[str, Any]] = {}
    total_allowed = 0
    total_denied = 0
    total_failed = 0
    total_bytes_in = 0
    total_bytes_out = 0

    for ev in events:
        result = ev.get("result")
        host = ev.get("host") or "<unknown>"
        port = ev.get("port")
        key = f"{host}:{port}" if port else host

        if key not in by_host:
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
            if result not in entry["reasons"]:
                entry["reasons"].append(result)
        elif result in _FAILED_RESULTS:
            entry["failed"] += 1
            total_failed += 1
            if result not in entry["reasons"]:
                entry["reasons"].append(result)
        else:
            entry["failed"] += 1
            total_failed += 1

        entry["bytes_in"] += b_in
        entry["bytes_out"] += b_out
        total_bytes_in += b_in
        total_bytes_out += b_out

    unique_hosts = {e["host"] for e in by_host.values()
                    if e["host"] != "<unknown>"}

    total = total_allowed + total_denied + total_failed
    return {
        "total_connections": total,
        "allowed": total_allowed,
        "denied": total_denied,
        "failed": total_failed,
        "unique_hosts": len(unique_hosts),
        "total_bytes_in": total_bytes_in,
        "total_bytes_out": total_bytes_out,
        "hosts": sorted(by_host.values(), key=lambda e: e["host"]),
    }


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KiB"
    return f"{n / (1024 * 1024):.1f} MiB"


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
                total, hosts, bytes_in, bytes_out, out_path,
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
                bytes_in, bytes_out, out_path,
            )
        return summary
    except Exception:  # noqa: BLE001 — never fail lifecycle
        log.debug(
            "finalize_egress_summary failed for %s",
            output_dir, exc_info=True,
        )
        return None
