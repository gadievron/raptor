"""Frida evidence ingestion for binary understanding."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from packages.frida import parse_events
from packages.frida.evidence import discover_evidence

from .evidence import EvidenceRecord, EvidenceTier, make_evidence


def load_runtime_evidence(
    runtime_dir: Path,
    *,
    target_path: str,
    binary_sha256: str,
) -> tuple[list[dict[str, Any]], list[EvidenceRecord]]:
    """Load matching Frida output without executing the target.

    Runtime observation is opt-in: callers pass a run directory produced by
    `/frida`. This function never silently spawns or attaches to binaries.
    """
    events: list[dict[str, Any]] = []
    records: list[EvidenceRecord] = []
    matches = discover_evidence([Path(runtime_dir)], target_path=target_path)
    for match in matches:
        event_path = match.run_dir / "events.jsonl"
        parsed: list[dict[str, Any]] = []
        for event in parse_events(event_path, max_lines=100000):
            payload = event.get("payload")
            if event.get("type") != "send" or not isinstance(payload, dict):
                continue
            if payload.get("_meta"):
                continue
            parsed.append({
                "category": payload.get("category"),
                "fn": payload.get("fn"),
                "args": payload.get("args") or {},
                "tid": payload.get("tid"),
                "caller": payload.get("caller"),
                "caller_module": payload.get("caller_module"),
                "caller_module_base": payload.get("caller_module_base"),
                "caller_offset": payload.get("caller_offset"),
                "backtrace": payload.get("backtrace") or [],
                "backtrace_frames": payload.get("backtrace_frames") or [],
                "run_dir": str(match.run_dir),
            })
        events.extend(parsed)
        records.append(make_evidence(
            binary_sha256,
            kind="runtime_trace",
            source="frida_events",
            summary=f"Loaded {len(parsed)} Frida API events from {match.run_dir.name}",
            tier=EvidenceTier.OBSERVED_RUNTIME,
            confidence="confirmed" if parsed else "candidate",
            reproducible=False,
            tool="frida",
            location=str(event_path),
            data={
                "run_dir": str(match.run_dir),
                "events": len(parsed),
                "has_drcov": match.has_drcov,
                "has_events": match.has_events,
            },
        ))
    return events, records


__all__ = ["load_runtime_evidence"]
