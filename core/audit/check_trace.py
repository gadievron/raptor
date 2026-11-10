"""Durable, reporting-only observations of existing tool-chain results."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from typing import TYPE_CHECKING

from core.json import dumps_artifact, dumps_canonical, loads, save_json

from .record import append_audit_log, load_verified_audit_log
from .verification_results import SOURCE_CHANGED_REASON, SOURCE_INPUT_REASON, SOURCE_INPUT_RULE, SOURCE_VALIDATION_TOOL

if TYPE_CHECKING:
    from .claim_verification import ClaimVerification


logger = logging.getLogger(__name__)
CHECK_RESULTS_FILENAME = "verification-checks.json"
CLAIM_OBSERVATIONS_FILENAME = "claim-observations.json"
SOURCE_VALIDATION_RULE = "source-version-drift"

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


def record_claim_observations(
    out_dir: Path | None, *, file: str, function: str, line_start: int,
    verifications: Iterable["ClaimVerification"],
) -> None:
    """Retain aggregation inputs, without admitting their labels as evidence.

    Producer bindings remain separate from consumer context. Completeness
    flags describe serialization only, never scope validity or proof. The
    bounded payload and metadata keep the event below the trail reader limit.
    """
    if out_dir is None:
        return
    try:
        records = tuple(verifications)
        observations = [{"hypothesis": record.hypothesis,
                         "receipt_labels": list(record.receipts),
                         "proposed_refutation": record.refuted} for record in records]
        bindings = [asdict(record.binding) if record.binding is not None else None for record in records]
        omissions = []

        def metadata(value, byte_limit, name):
            try:
                if len(dumps_artifact(value, indent=None).encode("utf-8")) <= byte_limit:
                    return value
                omissions.append(f"{name}_size_limit")
            except Exception as exc:
                omissions.append(f"{name}_serialization:{type(exc).__name__}")
            return None

        producer_bindings = metadata(bindings, 128 * 1024, "producer_bindings")
        claim_revisions = metadata([record.claim_revision.reference() if record.claim_revision is not None else None
                                    for record in records], 128 * 1024, "claim_revisions")
        consumer = metadata({"file": file, "function": function, "line_start": line_start},
                            16 * 1024, "consumer_scope")
        append_audit_log(Path(out_dir), {
            "action": "ihv_claim_observations", "schema_version": 1, "id": uuid4().hex,
            "role": "unadjudicated_observation", "observation_count": len(records),
            "consumer_scope": consumer, "consumer_scope_complete": consumer is not None,
            "producer_bindings": producer_bindings,
            "producer_bindings_complete": producer_bindings is not None,
            "claim_revisions": claim_revisions,
            "claim_revisions_complete": claim_revisions is not None,
            "observations": _snapshot(SimpleNamespace(details=observations)),
            "metadata_omissions": omissions,
        })
    except Exception:
        # Reporting does not change the existing adjudication or buy a retry.
        logger.warning("could not record IHV claim observations", exc_info=True)


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
        claim_revision = getattr(results, "claim_revision", None)
        if claim_revision is not None:
            record["claim_reference"] = claim_revision.event_reference()
        append_audit_log(Path(out_dir), record)
    except Exception:
        # Reporting must never turn a successful check into a tool error.
        logger.warning("could not record verification check", exc_info=True)


def record_source_input_rejection(out_dir, results, *, current_source, requested_tools) -> None:
    """Record an unbound excerpt without claiming that a checker executed."""
    record_check_observation(
        out_dir, results, tool=SOURCE_VALIDATION_TOOL, verdict="inconclusive",
        rule_id=SOURCE_INPUT_RULE, reason=SOURCE_INPUT_REASON,
        result=SimpleNamespace(outcome="inconclusive", details={
            "source_identity_at_dispatch": asdict(current_source),
            "requested_tools": sorted(requested_tools), "checker_execution": "not_run",
        }),
    )


def record_source_invalidation(out_dir, results, *, source_identity_after, prior_receipts, prior_outcomes,
                               phase="chain_completion") -> None:
    """Retain the source-version withdrawal alongside raw checker results.

    This is a file-identity check, not another vulnerability checker. The
    scope retains the dispatch identity so the reader can identify exactly
    which historical observations lost applicability. Payload truncation
    cannot erase that scoped invalidation event.
    """
    record_check_observation(
        out_dir, results, tool=SOURCE_VALIDATION_TOOL, verdict="inconclusive",
        rule_id=SOURCE_VALIDATION_RULE, reason=SOURCE_CHANGED_REASON,
        result=SimpleNamespace(outcome="inconclusive", details={
            "source_identity_after": asdict(source_identity_after) if source_identity_after else None,
            "prior_receipts": list(prior_receipts),
            "prior_outcomes": [asdict(outcome) for outcome in prior_outcomes],
            "phase": phase,
        }),
    )


def record_claim_scope_rejection(out_dir, binding, *, attempted_scope, reason, receipts) -> None:
    """Retain a rejected handoff without attributing its proof to the consumer.

    The event's scope remains the producer's scope; attempted_scope is only
    consumer context. A legacy record's missing scope is never backfilled.
    """
    from .verification_results import VerificationScope

    reported = binding if binding is not None else VerificationScope("", "", 0, "")
    record_check_observation(
        out_dir, reported, tool="claim_binding", verdict="inconclusive",
        rule_id="claim-scope-rejected", reason=reason,
        result=SimpleNamespace(outcome="inconclusive", details={
            "attempted_scope": attempted_scope, "prior_receipts": list(receipts),
            "producer_scope_recorded": binding is not None,
        }),
    )


def record_synthesis_exclusion(out_dir, binding, *, attempted_scope, excluded_receipts) -> None:
    """Retain receipt-policy exclusions without inventing producer scope."""
    from .verification_results import VerificationScope

    reported = binding if binding is not None else VerificationScope("", "", 0, "")
    record_check_observation(
        out_dir, reported, tool="synthesis_admission", verdict="inconclusive",
        rule_id="synth-receipt-excluded", reason="synthesized receipt is not promotion evidence for this claim",
        result=SimpleNamespace(outcome="inconclusive", details={
            "attempted_scope": attempted_scope, "excluded_receipts": excluded_receipts,
            "producer_scope_recorded": binding is not None,
        }),
    )


def _apply_source_invalidations(checks: list[dict]) -> dict:
    """Reporting-only links to admitted, exactly scoped source withdrawals.

    Never infer freshness from a missing event. Identity covers one source
    file, not dependencies, build assumptions or later publication. Existing
    event admission handles replay and conflicting IDs before this join.
    """
    withdrawals = defaultdict(list)
    for check in checks:
        identity = check["scope"].get("source_identity")
        if (check.get("tool") == SOURCE_VALIDATION_TOOL
                and check.get("rule_id") == SOURCE_VALIDATION_RULE
                and check.get("outcome") == "inconclusive"
                and isinstance(identity, dict) and identity.get("sha256") and identity.get("version")):
            withdrawals[dumps_canonical(check["scope"])].append(check["id"])
    invalidated = 0
    if withdrawals:
        for check in checks:
            if check.get("outcome") not in {"confirmed", "refuted"}:
                continue
            ids = withdrawals.get(dumps_canonical(check["scope"]))
            if ids:
                check["source_applicability"] = {"status": "invalidated", "validation_ids": sorted(ids)}
                invalidated += 1
    return {
        "invalidations": sum(len(ids) for ids in withdrawals.values()),
        "invalidated_observations": invalidated,
        "unbound_inputs": sum(check.get("tool") == SOURCE_VALIDATION_TOOL
                             and check.get("rule_id") == SOURCE_INPUT_RULE
                             and check.get("outcome") == "inconclusive" for check in checks),
        "scope": "source_file_only", "revalidated_at_export": False,
    }


def _summarize_observations(checks: list[dict]) -> dict:
    """Count retained records, not executions, unique defects, or proofs.

    Payload completeness describes serialization only. An explicit empty
    assumptions list is still a report from the checker; an absent field
    does not mean that the check required no assumptions.
    """
    outcomes: Counter[str] = Counter()
    by_tool: defaultdict[str, Counter[str]] = defaultdict(Counter)
    payloads: Counter[str] = Counter()
    identities: Counter[str] = Counter()
    assumptions: Counter[str] = Counter()
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


def _admit_observation_events(rows, *, action: str, valid_payload: Callable[[dict], bool]) -> tuple[list[dict], list[dict], dict]:
    """Deduplicate deliveries and quarantine every variant of a reused ID.

    Authentication is the caller's responsibility. This admission concerns
    event identity only, never applicability, analysis completeness or proof.
    Compare the entire signed payload, excluding its transport integrity token;
    even a change in scope or limitations is a conflicting event, not an update.
    Keep first-delivery order for display, without using it to choose a winner.
    The append-only log retains all deliveries, including rejected records.
    """
    events: dict[str, dict[bytes, dict]] = {}
    input_records = duplicate_records = invalid_records = 0
    for row in rows:
        if row.get("action") != action or row.get("schema_version") != 1:
            continue
        input_records += 1
        event_id = row.get("id")
        if not isinstance(event_id, str) or not event_id.strip():
            invalid_records += 1
            continue
        if not valid_payload(row):
            invalid_records += 1
            # Keep its identity: a malformed variant must also quarantine a
            # well-formed event carrying the same ID, in either arrival order.
        payload = {k: v for k, v in row.items() if k != "integrity"}
        fingerprint = sha256(dumps_canonical(payload).encode("utf-8")).digest()
        variants = events.setdefault(event_id, {})
        if fingerprint in variants:
            duplicate_records += 1
        else:
            variants[fingerprint] = payload
    checks: list[dict] = []
    quarantined: list[dict] = []
    conflicting_ids = 0
    for variants in events.values():
        if len(variants) == 1:
            payload = next(iter(variants.values()))
            if valid_payload(payload):
                checks.append(payload)
        else:
            conflicting_ids += 1
            quarantined.extend(variants.values())
    admission = {
        "input_records": input_records, "accepted_records": len(checks),
        "duplicate_records": duplicate_records, "invalid_records": invalid_records,
        "conflicting_ids": conflicting_ids, "quarantined_records": len(quarantined),
    }
    return checks, quarantined, admission


def _admit_check_events(rows) -> tuple[list[dict], list[dict], dict]:
    return _admit_observation_events(rows, action="verification_check",
                                     valid_payload=lambda row: isinstance(row.get("scope"), dict))


def _claim_event_shape(row: dict) -> bool:
    """Validate the observation envelope, never the claims' truth or scope."""
    count = row.get("observation_count")
    snapshot = row.get("observations")
    if (row.get("role") != "unadjudicated_observation" or type(count) is not int or count < 0
            or not isinstance(snapshot, dict) or type(snapshot.get("complete")) is not bool):
        return False
    if snapshot["complete"]:
        data = snapshot.get("data")
        details = data.get("details") if isinstance(data, dict) else None
        if not isinstance(details, list) or len(details) != count:
            return False
    elif not isinstance(snapshot.get("reason"), str) or not snapshot["reason"]:
        return False
    for field in ("consumer_scope", "producer_bindings", "claim_revisions"):
        if field == "claim_revisions" and field not in row:
            continue  # Earlier signed summaries have unavailable lineage.
        value = row.get(field)
        complete = row.get(field + "_complete")
        if type(complete) is not bool or complete != (value is not None):
            return False
        if complete:
            if field == "consumer_scope":
                if not isinstance(value, dict):
                    return False
            elif not isinstance(value, list) or len(value) != count:
                return False
    return True


def _admit_claim_events(rows) -> tuple[list[dict], list[dict], dict]:
    return _admit_observation_events(rows, action="ihv_claim_observations", valid_payload=_claim_event_shape)


def write_check_results(export: dict, out_dir: Path) -> None:
    """Export run-bound checks and link them to findings and clean reviews.

    Only verified event rows are admitted. Links describe claim/location
    correspondence, not fresh source validation or verdict authority.
    All observations, including checks of clean functions, remain in the
    sidecar; channels that bypass this observation seam remain unavailable.
    """
    status = "unavailable"
    checks: list[dict] = []
    artifact = None
    retained_summary = _summarize_observations([])
    admission = None
    source_validation = None
    claim_observations: list[dict] = []
    claim_admission = None
    events = []
    events_available = False
    try:
        events = load_verified_audit_log(out_dir)
        events_available = True
        checks, quarantined, admission = _admit_check_events(events)
        source_validation = _apply_source_invalidations(checks)
        retained_summary = _summarize_observations(checks)
        save_json(out_dir / CHECK_RESULTS_FILENAME, {
            "schema_version": 1, "history_complete": False, "checks": checks,
            "quarantined_checks": quarantined, "event_admission": admission,
            "source_validation": source_validation,
            "summary": retained_summary,
            "limitations": [
                "Only retained tool-chain observations are included; missing checks are unavailable.",
                "Repeated event IDs count once; conflicting payloads are quarantined without claim links.",
                "Source identities are captured at dispatch, not revalidated at export.",
                "Source invalidations withdraw applicability without deleting raw checker outcomes.",
                "A checker outcome does not establish that the final finding is correct.",
                "Payload completeness concerns serialization, not proof or analysis completeness.",
            ],
        })
        artifact = CHECK_RESULTS_FILENAME
        status = "recorded" if checks else "unavailable"
    except Exception:
        status = "export_error"
        checks = []
        source_validation = None
        retained_summary = _summarize_observations([])
        logger.warning("could not export verification checks", exc_info=True)

    claim_artifact = None
    claim_status = "unavailable"
    try:
        if not events_available:
            raise ValueError("authenticated audit observations unavailable")
        claim_observations, quarantined_claims, claim_admission = _admit_claim_events(events)
        save_json(out_dir / CLAIM_OBSERVATIONS_FILENAME, {
            "schema_version": 1, "role": "unadjudicated_observation", "history_complete": False,
            "claim_observations": claim_observations,
            "quarantined_claim_observations": quarantined_claims,
            "event_admission": claim_admission,
            "limitations": [
                "Authentication and event admission establish provenance, not claim truth or applicability.",
                "Retained events are not distinct claims or checker executions.",
                "Lineage describes intake history, not fresh source or binary image identity.",
                "Missing or partial statements and metadata remain unavailable.",
                "Proposed refutations and receipt labels confer no verdict authority.",
            ],
        })
        claim_artifact = CLAIM_OBSERVATIONS_FILENAME
        claim_status = "recorded" if claim_observations else "unavailable"
    except Exception:
        claim_status = "export_error"
        claim_observations = []
        claim_admission = None
        logger.warning("could not export claim observations", exc_info=True)

    by_location = defaultdict(list)
    for check in checks:
        scope = check["scope"]
        key = (scope.get("file"), scope.get("function"), scope.get("line_start"))
        by_location[key].append(check)
    findings = export.get("findings", [])
    locations = Counter((f.get("file"), f.get("function"), f.get("line")) for f in findings)
    clean_traces = export.get("clean_review_traces", [])
    for trace in clean_traces:
        scope = trace.get("scope") or {}
        locations[(scope.get("file"), scope.get("function"), scope.get("line"))] += 1

    def link_hypotheses(trace, key):
        for review in trace.get("hypothesis_reviews", []):
            refs = [
                {"id": check["id"]}
                for check in by_location.get(key, [])
                if review.get("hypothesis") and check["scope"].get("hypothesis") == review["hypothesis"]
            ] if locations[key] == 1 else []
            review["check_results"] = {
                "artifact": artifact, "references": refs,
                "status": ("export_error" if status == "export_error" else
                           "ambiguous_scope" if locations[key] > 1 else
                           "recorded" if refs else "unavailable"),
            }

    matching: list[dict] = []
    other_claims: list[dict] = []
    linked_objects = set()
    findings_with_matches = 0
    for finding in findings:
        trace = finding.get("verification_trace")
        if not isinstance(trace, dict):
            continue
        key = (finding.get("file"), finding.get("function"), finding.get("line"))
        link_hypotheses(trace, key)
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
    clean_with_matches = 0
    for trace in clean_traces:
        scope = trace.get("scope") or {}
        key = (scope.get("file"), scope.get("function"), scope.get("line"))
        link_hypotheses(trace, key)
        refs = [
            {"id": check["id"], "matches_final_claim": check["scope"].get("hypothesis") == trace.get("claim")}
            for check in by_location.get(key, [])
        ] if locations[key] == 1 else []
        clean_with_matches += any(ref["matches_final_claim"] for ref in refs)
        trace["check_results"] = {
            "artifact": artifact, "references": refs,
            "status": ("export_error" if status == "export_error" else
                       "ambiguous_scope" if locations[key] > 1 else
                       "recorded" if refs else "unavailable"),
        }
    trace_statuses = Counter(
        finding["verification_trace"]["check_results"]["status"]
        if isinstance(finding.get("verification_trace"), dict) else "unavailable"
        for finding in findings
    )
    export["verification_summary"] = {
        "schema_version": 1, "history_complete": False, "artifact": artifact, "export_status": status,
        "event_admission": admission,
        "source_validation": source_validation,
        "claim_observations": {
            "role": "unadjudicated_observation", "history_complete": False,
            "artifact": claim_artifact, "retained_events": len(claim_observations),
            "event_admission": claim_admission, "status": claim_status,
        },
        "findings": {"total": len(findings), "with_matching_observations": findings_with_matches,
                     "without_matching_observations": len(findings) - findings_with_matches,
                     "trace_statuses": dict(trace_statuses)},
        "clean_reviews": {"total": len(clean_traces), "with_matching_observations": clean_with_matches,
                          "without_matching_observations": len(clean_traces) - clean_with_matches},
        "observations": {
            "retained": retained_summary,
            "matching_final_claim": _summarize_observations(matching),
            "other_claims": _summarize_observations(other_claims),
            "not_linked_to_findings": _summarize_observations([c for c in checks if id(c) not in linked_objects]),
        },
        "limitations": [
            "Counts describe retained observations, not distinct executions or proven defects.",
            "Matching compares claim text and location; source freshness is not revalidated.",
            "Source invalidations withdraw applicability; raw outcomes remain historical observations.",
            "Hypothesis links identify recorded checks, not support for a counterargument.",
            "Missing observations do not establish that no check ran.",
        ],
    }
