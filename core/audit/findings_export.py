"""Structured findings export with evidence chains.

Converts raw audit outcomes into the output contract: each finding
carries a graded evidence chain, impact assessment, and downstream
consumer metadata. The export feeds /validate, /exploit, and
report generation.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from .evidence_grade import (
    GradedEvidence,
    finding_confidence,
    grade_evidence_record,
    grade_review_result,
    is_tool_evidence,
)

logger = logging.getLogger(__name__)


def build_graded_finding(
    outcome: Any,
    evidence_record: Any | None = None,
) -> dict[str, Any]:
    """Build a finding dict with graded evidence chain.

    Combines mechanical evidence (from EvidenceRecord) with LLM review
    evidence (from ReviewOutcome.review_result) into a single ordered
    chain with source tags and confidence levels.

    The exported ``confidence`` is computed only from
    hypothesis-correlated evidence: the review-derived items plus tool
    receipts (which pass correlation gates before they are stamped).
    Ambient mechanical signals from the evidence record — e.g. a Joern
    flow that exists somewhere in the function but was never matched
    to THIS hypothesis — stay in the exported chain as context but no
    longer export an LLM-only guess as ``confidence=high``.
    """
    chain: list[GradedEvidence] = []

    if evidence_record is not None:
        chain.extend(grade_evidence_record(evidence_record))

    review_result = getattr(outcome, "review_result", None) or {}
    evidence_tool = getattr(outcome, "evidence_tool", "")
    review_items = grade_review_result(review_result, evidence_tool)
    chain.extend(review_items)

    if is_tool_evidence(evidence_tool):
        confidence = finding_confidence(chain)
    else:
        confidence = finding_confidence(review_items)

    file_val = getattr(outcome, "file", "")
    func_val = getattr(outcome, "function", "")
    line_val = getattr(outcome, "line", 0)
    status_val = getattr(outcome, "status", "")
    hypothesis_val = getattr(outcome, "hypothesis", "")

    finding_id = getattr(outcome, "finding_id", "")
    if not finding_id:
        finding_id = f"{file_val}:{func_val}:{line_val}"

    # Verification tier: prefer a live recompute (post-resolution
    # dispatch state), fall back to the journaled attribute.
    tier = ""
    compute = getattr(outcome, "compute_tier", None)
    if callable(compute):
        try:
            tier = compute() or ""
        except Exception:  # noqa: BLE001 — export must not fail the run
            tier = ""
    if not tier:
        tier = getattr(outcome, "verification_tier", "") or "speculative"

    finding: dict[str, Any] = {
        "id": finding_id,
        "file": file_val,
        "function": func_val,
        "line": line_val,
        "status": status_val,
        "hypothesis": hypothesis_val,
        "title": hypothesis_val[:120] if hypothesis_val else f"{status_val} in {func_val}",
        "vuln_type": review_result.get("vuln_type", ""),
        "depth": getattr(outcome, "depth", "L1"),
        "confidence": confidence.value,
        "verification_tier": tier,
        "evidence_chain": [e.to_dict() for e in chain],
    }
    if status_val == "dark":
        # Tool-blind bucket: no mechanical channel can decide this
        # class — exactly the findings /validate exists to judge.
        finding["needs_validation"] = True

    # Hypothesis multiplicity: the review's full hypotheses array.
    # A multi-bug function used to export as one finding with one
    # hypothesis string — the sibling mechanisms (and their
    # confidences) were invisible to the operator and to /validate.
    hyp_entries = getattr(outcome, "hypotheses", None) or []
    if not hyp_entries and review_result:
        hyp_entries = review_result.get("hypotheses") or []
    hyp_entries = [
        h for h in hyp_entries
        if isinstance(h, dict) and h.get("mechanism")
    ]
    if hyp_entries:
        finding["hypothesis_multiplicity"] = {
            "count": len(hyp_entries),
            "mechanisms": [
                {
                    "mechanism": (h.get("mechanism") or "")[:200],
                    "confidence": (h.get("confidence") or "").lower(),
                }
                for h in hyp_entries[:8]
            ],
        }

    # Secondary-hypothesis tool confirmations (dispatch lane receipts).
    secondary = review_result.get("secondary_confirmations")
    if secondary:
        finding["secondary_confirmations"] = secondary

    if review_result.get("cwe_class"):
        finding["cwe_class"] = review_result["cwe_class"]

    impact = review_result.get("impact")
    if impact:
        finding["impact"] = impact

    spec_dev = review_result.get("spec_deviation")
    if spec_dev and spec_dev.get("deviation"):
        finding["spec_deviation"] = spec_dev

    ts_viol = review_result.get("typestate_violation")
    if ts_viol and ts_viol.get("violation_kind"):
        finding["typestate_violation"] = ts_viol

    # File pile-up dampening audit trail (see pipeline.dampen_file_pileup):
    # the demotion/collapse record travels with the exported finding so
    # the operator can see WHY a status was softened.
    dampening = review_result.get("file_dampening")
    if dampening:
        finding["file_dampening"] = dampening

    discovery_sources = []
    if evidence_record is not None:
        if getattr(evidence_record, "joern_flows", None):
            discovery_sources.append("joern")
        if getattr(evidence_record, "codeql_alerts", None):
            discovery_sources.append("codeql")
        if getattr(evidence_record, "taint_approx", None):
            discovery_sources.append("taint_approx")
        if getattr(evidence_record, "binary_layer0_findings", None):
            discovery_sources.append("layer0")
        if getattr(evidence_record, "semgrep_results", None):
            discovery_sources.append("semgrep")
    if review_result:
        discovery_sources.append("llm_review")
    review_depth = getattr(outcome, "review_depth", "")
    tokens_spent = getattr(outcome, "tokens_spent", 0)
    confirmed_by = getattr(outcome, "confirmed_by", [])
    discovered_by_attr = getattr(outcome, "discovered_by", "")

    finding["discovery"] = {
        "sources": discovery_sources or ["llm_review"],
        "evidence_tool": evidence_tool or "none",
        "discovered_by": discovered_by_attr or (discovery_sources[0] if discovery_sources else "llm_review"),
        "confirmed_by": confirmed_by if isinstance(confirmed_by, list) else [],
        "review_depth": review_depth or "investigate",
        "tokens_spent": tokens_spent or 0,
    }

    run_id = getattr(outcome, "run_id", "")
    checker_id = getattr(outcome, "checker_id", "")
    summary_source = getattr(outcome, "summary_source", "")
    finding["provenance"] = {
        "model": getattr(outcome, "model", ""),
        "cost_usd": getattr(outcome, "cost_usd", 0.0),
        "duration_s": getattr(outcome, "duration_s", 0.0),
        "run_id": run_id,
        "checker_id": checker_id,
        "summary_source": summary_source or ("joern" if discovery_sources and "joern" in discovery_sources else "llm"),
    }
    finding["model"] = getattr(outcome, "model", "")
    finding["cost_usd"] = getattr(outcome, "cost_usd", 0.0)

    callers = review_result.get("callers", [])
    callees = review_result.get("callees", [])
    entry_point = review_result.get("entry_point", "")
    if callers or callees or entry_point:
        finding["context"] = {}
        if callers:
            finding["context"]["callers"] = callers[:10]
        if callees:
            finding["context"]["callees"] = callees[:10]
        if entry_point:
            finding["context"]["entry_point"] = entry_point

    return finding


def export_findings(
    outcomes: list[Any],
    evidence_index: dict[str, Any] | None = None,
    attack_chains: list[Any] | None = None,
    *,
    out_dir: Path | None = None,
    run_id: str = "",
) -> dict[str, Any]:
    """Export all findings with evidence chains and attack chains.

    Returns a structured dict suitable for writing to findings-graded.json.

    When ``out_dir`` is given, the promotion-without-tool-evidence
    alarm sweeps the FINAL outcome statuses here (post-loop promotions
    run after the per-review journal writes, so the export is the
    second chokepoint that sees them).  Alarm-only; the export output
    is unchanged.
    """
    if out_dir is not None:
        try:
            from .promotion_alarm import check_outcomes
            check_outcomes(
                Path(out_dir), outcomes, stage="findings-export",
                run_id=run_id,
            )
        except Exception:
            logger.debug("promotion alarm export sweep failed", exc_info=True)

    findings: list[dict[str, Any]] = []
    for outcome in outcomes:
        status = getattr(outcome, "status", "clean")
        # "dark" is exported alongside finding/suspicious: it is the
        # "tool-blind, needs concrete verification" bucket — excluding
        # it made every hypothesis the gates routed to dark invisible
        # to the operator and to /validate, the one pipeline built to
        # judge tool-blind findings.
        if status not in ("finding", "suspicious", "dark"):
            continue

        key = f"{getattr(outcome, 'file', '')}:{getattr(outcome, 'function', '')}"
        ev_record = evidence_index.get(key) if evidence_index else None
        finding = build_graded_finding(outcome, ev_record)
        findings.append(finding)

    result: dict[str, Any] = {
        "findings": findings,
        "stats": {
            "total": len(findings),
            "high_confidence": sum(
                1 for f in findings if f["confidence"] == "high"
            ),
            "medium_confidence": sum(
                1 for f in findings if f["confidence"] == "medium"
            ),
            "low_confidence": sum(
                1 for f in findings if f["confidence"] == "low"
            ),
            "dark": sum(
                1 for f in findings if f["status"] == "dark"
            ),
        },
    }

    if attack_chains:
        result["attack_chains"] = [
            c.to_dict() if hasattr(c, "to_dict") else c
            for c in attack_chains
        ]

    return result


def write_graded_findings(
    export: dict[str, Any],
    out_dir: Path,
) -> Path:
    """Write findings-graded.json to the run directory."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "findings-graded.json"
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def format_findings_summary(export: dict[str, Any]) -> str:
    """Render a human-readable summary of graded findings."""
    stats = export.get("stats", {})
    total = stats.get("total", 0)
    if total == 0:
        return "No findings."

    lines = [f"**{total} findings**"]

    high = stats.get("high_confidence", 0)
    med = stats.get("medium_confidence", 0)
    low = stats.get("low_confidence", 0)

    parts = []
    if high:
        parts.append(f"{high} high-confidence")
    if med:
        parts.append(f"{med} medium-confidence")
    if low:
        parts.append(f"{low} low-confidence")
    if parts:
        lines.append(f"Confidence: {', '.join(parts)}")

    dark = stats.get("dark", 0)
    if dark:
        lines.append(
            f"Dark (tool-blind, needs concrete verification): {dark} "
            f"— route to /validate"
        )

    chains = export.get("attack_chains", [])
    if chains:
        confirmed = sum(
            1 for c in chains
            if (c.get("chain_status") or "") == "confirmed"
        )
        lines.append(f"Attack chains: {len(chains)} ({confirmed} confirmed)")

    return "\n".join(lines)
