"""Reporting-only verification provenance; never grants verdict authority."""

from __future__ import annotations

from typing import Any

from .verification_results import ClaimRefutation


def build_verification_trace(outcome: Any, finding: dict[str, Any]) -> dict[str, Any]:
    """Describe recorded evidence without inferring checks from tool names.

    Channel sets are cumulative bookkeeping, not a mutually exclusive
    per-attempt history. ``None`` means the producer did not retain that
    information; an empty list means it retained no members. Receipt
    markers retain their existing grading semantics but do not substitute
    for raw check results. Model assumptions remain explicitly unverified.
    """
    channels = {}
    for state, attribute in (
        ("dispatched", "tools_dispatched"),
        ("errored", "tools_errored"),
        ("skipped", "tools_skipped"),
        ("inconclusive", "tools_inconclusive"),
    ):
        values = getattr(outcome, attribute, None)
        channels[state] = sorted(str(v) for v in values) if values is not None else None

    hypotheses = (
        getattr(outcome, "trace_hypotheses", None)
        or getattr(outcome, "hypotheses", None)
        or (getattr(outcome, "review_result", None) or {}).get("hypotheses")
        or []
    )
    assumptions = [
        {"hypothesis": h.get("mechanism") or h.get("text") or "",
         "property": h["assumed_property"], "origin": "review", "verified": False}
        for h in hypotheses
        if isinstance(h, dict) and isinstance(h.get("assumed_property"), str)
        and h["assumed_property"]
    ]
    checks = []
    for receipt in getattr(outcome, "claim_refutations", ()) or ():
        if isinstance(receipt, ClaimRefutation):
            checks.append({
                **receipt.to_record(),
                # Copies can retain receipts for an older hypothesis.
                # This textual match is not a fresh source validation.
                "matches_final_claim": (
                    receipt.file == finding["file"]
                    and receipt.function == finding["function"]
                    and receipt.line_start == finding["line"]
                    and receipt.hypothesis == finding["hypothesis"]
                ),
                "source_revalidated_at_export": False,
            })

    discovery = finding["discovery"]
    return {
        "schema_version": 1,
        "derivation": getattr(outcome, "trace_derivation", "outcome"),
        "claim": finding["hypothesis"],
        "scope": {"file": finding["file"], "function": finding["function"],
                  "function_qualified": getattr(outcome, "function_qualified", ""),
                  "line": finding["line"]},
        "final_status": finding["status"],
        "verification_tier": finding["verification_tier"],
        "receipt_scope": getattr(outcome, "receipt_scope", None),
        "evidence_marker": discovery["evidence_tool"],
        "confirming_markers": list(discovery["confirmed_by"]),
        "channels": channels,
        "claim_checks": checks,
        "claim_check_details": "recorded" if checks else "unavailable",
        "assumptions": assumptions,
        "limitations": [
            "Markers are provenance, not raw proof results.",
            "Channel states are cumulative and do not identify individual attempts.",
            "Claim checks may cover earlier claims; source freshness is not rechecked at export.",
            "Missing check details are unavailable, not a refutation or confirmation.",
        ],
    }
