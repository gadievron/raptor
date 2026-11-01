"""Read-only campaign correlation over authenticated sandbox denial records.

Derived summary buckets are deliberately ignored: their contents are not MAC'd.
Missing telemetry is uncertainty, never negative evidence of a signature.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from core.run import load_run_metadata
from core.sandbox import telemetry_mac
from core.sandbox.proxy import PROXY_EVENTS_FILENAME, PROXY_EVENTS_COUNT_FILENAME
from core.sandbox.summary import (
    AUDIT_DEGRADED_FILE, MAX_DENIALS_PER_RUN, SUMMARY_FILE,
    _triage_denials, classify_denial, get_run_posture,
)
from core.sandbox.triage import (
    TRIAGE_FILE, _BUDGET_MARKER_TYPES, _artifact_present, _load_json, _verify_summary,
    verify_triage_report,
)
from core.security.log_sanitisation import sanitise_for_terminal

_CATEGORIES = ("escape_primitives", "network_probing", "udp_egress",
               "filesystem_escape", "routine")
_SEVERITY_RANK = {"routine": 0, "elevated": 1, "critical": 2}


def _read_json(path: Path) -> dict | None:
    try:
        return _load_json(path)
    except (ValueError, RecursionError, OSError):
        return None


def _read_entry(directory: Path) -> dict:
    meta = load_run_metadata(directory)
    meta = meta if isinstance(meta, dict) else {}
    raw = _read_json(directory / SUMMARY_FILE)
    present = _artifact_present(directory / SUMMARY_FILE)
    marker = _artifact_present(directory / AUDIT_DEGRADED_FILE)
    report = _read_json(directory / TRIAGE_FILE)
    report_expected = _artifact_present(directory / TRIAGE_FILE) or bool(meta.get("sandbox_triage"))
    try:
        report_verified = report is not None and verify_triage_report(report, directory) == "verified"
    except (ValueError, TypeError, RecursionError):
        report_verified = False
    if report_verified and report is not None:
        # One-way only: an authenticated degraded report can condemn a missing
        # marker, never excuse missing or unverified summary evidence.
        marker = marker or bool(report.get("audit_degraded"))
        inputs = report.get("inputs")
        integrity = inputs.get("integrity") if isinstance(inputs, dict) else None
        if not isinstance(integrity, dict) or any(state != "verified" for state in integrity.values()):
            marker = True
    elif report_expected:
        marker = True
    evidence_present = (present or marker or _artifact_present(directory / TRIAGE_FILE)
                        or bool(meta.get("sandbox_triage"))
                        or _artifact_present(directory / PROXY_EVENTS_FILENAME)
                        or _artifact_present(directory / PROXY_EVENTS_COUNT_FILENAME))
    entry: dict[str, Any] = {"run": directory.name, "ts": str(meta.get("started_at") or meta.get("timestamp") or ""),
             "target": str(meta.get("target_path") or "unknown"),
             "integrity": "missing", "complete": False, "reason": "no denial summary",
             "evidence_present": evidence_present, "counts": Counter(), "labels": {},
             "categories": Counter(), "severity": None}
    if raw is None:
        if present:
            entry.update(integrity="tampered", reason="unreadable or malformed summary")
        return entry
    records = raw.get("denials")
    total = raw.get("total_denials")
    if (not isinstance(records, list) or len(records) > MAX_DENIALS_PER_RUN
            or not all(isinstance(r, dict) for r in records)
            or type(total) is not int or total != len(records)):
        entry.update(integrity="tampered", reason="invalid summary record/count shape")
        return entry
    if not telemetry_mac.key_usable():
        entry.update(integrity="unavailable", reason="telemetry provenance key unavailable")
        return entry
    try:
        usable, integrity = _verify_summary(raw, telemetry_mac.run_binding(directory),
                                            allow_legacy=False)
    except (TypeError, ValueError, OverflowError):
        usable, integrity = None, "tampered"
    if usable is None:
        entry.update(integrity=integrity, reason="summary provenance verification failed")
        return entry
    # A valid token is insufficient if this run could read the signing key.
    # Disk posture may only demote; parent memory remains authoritative.
    posture = get_run_posture(directory)
    disk_posture = raw.get("posture")
    if ((posture is not None and not posture.get("mac_key_hidden", True))
            or (isinstance(disk_posture, dict) and not disk_posture.get("mac_key_hidden", True))):
        entry.update(integrity="key_exposed", reason="run could read telemetry signing key")
        return entry
    try:
        budget_limited = False
        enforcement_records = []
        for record in records:
            dtype = record.get("type")
            if isinstance(dtype, str) and dtype in _BUDGET_MARKER_TYPES:
                if dtype != "audit_summary":
                    budget_limited = True
                elif record.get("sampled_keeps") or any(
                    bool(value) for value in (record.get("dropped_by_category") or {}).values()
                ):
                    budget_limited = True
                continue
            enforcement_records.append(record)
        triage = _triage_denials(enforcement_records)
        for record in enforcement_records:
            category, label = classify_denial(record)
            # Normalize only outer command whitespace. Path case, internal
            # whitespace and complete command tails remain identity-bearing.
            normalized = label if category in ("filesystem_escape", "escape_primitives") else label.strip()
            identity = hashlib.sha256((category + "\0" + normalized).encode()).hexdigest()
            entry["counts"][identity] += 1
            entry["labels"][identity] = (category, sanitise_for_terminal(normalized, max_len=512))
            entry["categories"][category] += 1
    except (AttributeError, TypeError, ValueError, OverflowError, UnicodeError):
        entry.update(integrity="tampered", reason="malformed denial fields",
                     counts=Counter(), labels={}, categories=Counter())
        return entry
    no_execution_evidence = bool(raw.get("cli_sandbox_disabled") or raw.get("floor_refusals"))
    complete = (not marker and not budget_limited and not no_execution_evidence
                and len(records) < MAX_DENIALS_PER_RUN)
    entry.update(integrity="verified", complete=complete, severity=triage["severity"],
                 reason=("" if complete else "incomplete audit, provenance, or sandbox execution"))
    return entry


def _metrics(entries: list[dict], counts: list[int]) -> dict[str, Any]:
    n = len(entries)
    hits = [i for i, count in enumerate(counts) if count]
    unknown_absences = sum(not e["complete"] and not count for e, count in zip(entries, counts))
    if not hits:
        trend = "stable" if all(e["complete"] for e in entries) else "unknown"
    elif n == 1:
        trend = "new"
    else:
        window = min(3, n - 1)
        recent = any(counts[-window:])
        earlier = any(counts[:-window])
        if recent and earlier:
            trend = "stable"
        elif recent:
            trend = "new" if all(e["complete"] for e in entries[:-window]) else "unknown"
        else:
            trend = "resolved" if all(e["complete"] for e in entries[-window:]) else "unknown"
    result = {"total_occurrences": sum(counts), "runs_seen": len(hits),
              "runs_considered": n, "persistence": round(len(hits) / n, 3),
              "persistence_upper": round((len(hits) + unknown_absences) / n, 3),
              "trend": trend}
    if hits:
        result.update(first_seen=entries[hits[0]]["ts"], last_seen=entries[hits[-1]]["ts"])
    return result


def correlate_campaign(run_dirs: list[Path]) -> dict[str, Any] | None:
    # Deduplicate directories so one run cannot manufacture recurrence.
    entries = [_read_entry(d) for d in dict.fromkeys(Path(d).resolve() for d in run_dirs)]
    if not any(e["evidence_present"] for e in entries):
        return None
    per_target: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        per_target[entry["target"]].append(entry)
    targets = {}
    for target, runs in sorted(per_target.items()):
        runs.sort(key=lambda e: (e["ts"], e["run"]))
        labels = {}
        for e in runs:
            labels.update(e["labels"])
        signatures = {}
        for identity, (category, example) in sorted(labels.items()):
            signatures[identity] = {"category": category, "example": example,
                                   **_metrics(runs, [e["counts"][identity] for e in runs])}
        categories = {}
        for category in _CATEGORIES:
            counts = [e["categories"][category] for e in runs]
            categories[category] = _metrics(runs, counts)
            categories[category]["examples"] = sorted({
                label for cat, label in labels.values() if cat == category})[:10]
        verified = sum(e["integrity"] == "verified" for e in runs)
        unknown = sum(not e["complete"] for e in runs)
        severity = max((e["severity"] or "routine" for e in runs), key=lambda level: _SEVERITY_RANK[level])
        if verified >= 4 and any(
            s["category"] != "routine" and s["runs_seen"] / len(runs) > 0.5
            for s in signatures.values()
        ):
            severity = {"routine": "elevated", "elevated": "critical", "critical": "critical"}[severity]
        if unknown and severity == "routine":
            severity = "elevated"
        targets[target] = {
            "runs_with_triage": verified, "runs_total": len(runs), "runs_unknown": unknown,
            "campaign_severity": severity, "integrity": "degraded" if unknown else "verified",
            "signatures": signatures, "categories": categories,
            "severity_history": [{k: e[k] for k in ("run", "ts", "severity", "integrity", "complete", "reason")}
                                 for e in runs[-50:]],
        }
    return {"schema_version": 2, "campaign_severity": max((t["campaign_severity"] for t in targets.values()),
                                      key=lambda level: _SEVERITY_RANK[level]),
            "integrity": "degraded" if any(t["runs_unknown"] for t in targets.values()) else "verified",
            "targets": targets}
