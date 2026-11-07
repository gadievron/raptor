"""Durable, reporting-only observations of existing tool-chain results."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

from core.json import dumps_artifact, loads, save_json

from .record import append_audit_log, load_verified_audit_log

logger = logging.getLogger(__name__)
CHECK_RESULTS_FILENAME = "verification-checks.json"

# Keep each observation comfortably below the audit log's 1 MiB row limit.
# Large checker dumps remain explicitly partial rather than disappearing.
_PAYLOAD_BYTES = 64 * 1024
_PREVIEW_CHARS = 4096


def _snapshot(result, request=None) -> dict:
    payload = {
        "request": request,
        "outcome": getattr(result, "outcome", None),
        "details": getattr(result, "details", None),
        "matches": getattr(result, "matches", None),
        "errors": getattr(result, "errors", None),
        "raw_output": getattr(result, "raw_output", None),
    }
    try:
        text = dumps_artifact(payload, indent=None)
        size = len(text.encode("utf-8"))
        if size > _PAYLOAD_BYTES:
            return {"complete": False, "size_bytes": size,
                    "preview": text[:_PREVIEW_CHARS], "reason": "payload_size_limit"}
        return {"complete": True, "data": loads(text)}
    except Exception as exc:
        return {"complete": False, "reason": f"payload_serialization:{type(exc).__name__}"}


def record_check_observation(out_dir, results, *, tool, verdict, rule_id, reason="", result=None, request=None) -> None:
    """Record a classified observation without changing the tool-chain result.

    The effective outcome and raw checker outcome are separate: a source
    drift or partial result may already have weakened the former. Checker
    assumptions, if supplied, remain in ``result.data.details``; absence
    means unavailable, never an assumption-free proof.
    """
    if out_dir is None:
        return
    try:
        file, function, line, hypothesis = results.scope
        record = {
            "action": "verification_check", "schema_version": 1, "id": uuid4().hex,
            "scope": {"file": file, "function": function, "line_start": line,
                      "hypothesis": hypothesis,
                      "source_identity": asdict(results.source_identity) if results.source_identity else None},
            "tool": tool, "outcome": verdict, "rule_id": rule_id, "reason": reason,
            "result": _snapshot(result, request=request),
        }
        append_audit_log(Path(out_dir), record)
    except Exception:
        # Reporting must never turn a successful check into a tool error.
        logger.warning("could not record verification check", exc_info=True)


def _summarize_observations(checks: list[dict]) -> dict:
    """Count retained records, not executions, unique defects, or proofs.

    Payload completeness describes serialization only. An explicit empty
    assumptions list is still a report from the checker; an absent field
    does not mean that the check required no assumptions.
    """
    outcomes = Counter()
    by_tool = defaultdict(Counter)
    payloads = Counter()
    identities = Counter()
    assumptions = Counter()
    for check in checks:
        tool = str(check.get("tool") or "unknown")
        outcome = str(check.get("outcome") or "unknown")
        outcomes[outcome] += 1
        by_tool[tool][outcome] += 1
        payload = check.get("result")
        payload = payload if isinstance(payload, dict) else {}
        complete = payload.get("complete")
        payloads["complete" if complete is True else "partial" if complete is False else "unavailable"] += 1
        identity = check["scope"].get("source_identity")
        identities["recorded" if isinstance(identity, dict) and identity.get("sha256") else "unavailable"] += 1
        data = payload.get("data")
        details = data.get("details") if isinstance(data, dict) else None
        reported = isinstance(details, dict) and details.get("assumptions") is not None
        assumptions["reported" if reported else "unavailable"] += 1
    return {
        "records": len(checks), "outcomes": dict(outcomes),
        "by_tool": {tool: dict(counts) for tool, counts in by_tool.items()},
        "payloads": {state: payloads[state] for state in ("complete", "partial", "unavailable")},
        "source_identity": {state: identities[state] for state in ("recorded", "unavailable")},
        "checker_assumptions": {state: assumptions[state] for state in ("reported", "unavailable")},
    }


def write_check_results(export: dict, out_dir: Path) -> None:
    """Export run-bound check observations and link them to graded findings.

    Only verified event rows are admitted. Links describe claim/location
    correspondence, not fresh source validation or verdict authority.
    All observations, including checks of clean functions, remain in the
    sidecar; channels that bypass this observation seam remain unavailable.
    """
    status = "unavailable"
    checks = []
    artifact = None
    retained_summary = _summarize_observations([])
    try:
        for row in load_verified_audit_log(out_dir):
            if row.get("action") != "verification_check" or row.get("schema_version") != 1:
                continue
            if not isinstance(row.get("scope"), dict) or not isinstance(row.get("id"), str):
                continue
            checks.append({k: v for k, v in row.items() if k != "integrity"})
        retained_summary = _summarize_observations(checks)
        save_json(out_dir / CHECK_RESULTS_FILENAME, {
            "schema_version": 1, "history_complete": False, "checks": checks,
            "summary": retained_summary,
            "limitations": [
                "Only retained tool-chain observations are included; missing checks are unavailable.",
                "Source identities are captured at dispatch, not revalidated at export.",
                "A checker outcome does not establish that the final finding is correct.",
                "Payload completeness concerns serialization, not proof or analysis completeness.",
            ],
        })
        artifact = CHECK_RESULTS_FILENAME
        status = "recorded" if checks else "unavailable"
    except Exception:
        status = "export_error"
        checks = []
        retained_summary = _summarize_observations([])
        logger.warning("could not export verification checks", exc_info=True)

    by_location = defaultdict(list)
    for check in checks:
        scope = check["scope"]
        key = (scope.get("file"), scope.get("function"), scope.get("line_start"))
        by_location[key].append(check)
    findings = export.get("findings", [])
    locations = Counter((f.get("file"), f.get("function"), f.get("line")) for f in findings)
    matching = []
    other_claims = []
    linked_objects = set()
    findings_with_matches = 0
    for finding in findings:
        trace = finding.get("verification_trace")
        if not isinstance(trace, dict):
            continue
        key = (finding.get("file"), finding.get("function"), finding.get("line"))
        if locations[key] > 1:
            trace["check_results"] = {"artifact": artifact, "references": [],
                                      "status": "export_error" if status == "export_error" else "ambiguous_scope"}
            continue
        refs = [{"id": check["id"],
                 "matches_final_claim": check["scope"].get("hypothesis") == finding.get("hypothesis")}
                for check in by_location.get(key, [])]
        findings_with_matches += any(ref["matches_final_claim"] for ref in refs)
        for check, ref in zip(by_location.get(key, []), refs):
            linked_objects.add(id(check))
            (matching if ref["matches_final_claim"] else other_claims).append(check)
        trace["check_results"] = {"artifact": artifact, "references": refs,
                                  "status": status if refs or status == "export_error" else "unavailable"}
    trace_statuses = Counter(
        finding["verification_trace"]["check_results"]["status"]
        if isinstance(finding.get("verification_trace"), dict) else "unavailable"
        for finding in findings
    )
    export["verification_summary"] = {
        "schema_version": 1, "history_complete": False, "artifact": artifact, "export_status": status,
        "findings": {"total": len(findings), "with_matching_observations": findings_with_matches,
                     "without_matching_observations": len(findings) - findings_with_matches,
                     "trace_statuses": dict(trace_statuses)},
        "observations": {
            "retained": retained_summary,
            "matching_final_claim": _summarize_observations(matching),
            "other_claims": _summarize_observations(other_claims),
            "not_linked_to_findings": _summarize_observations([c for c in checks if id(c) not in linked_objects]),
        },
        "limitations": [
            "Counts describe retained observations, not distinct executions or proven defects.",
            "Matching compares claim text and location; source freshness is not revalidated.",
            "Missing observations do not establish that no check ran.",
        ],
    }
