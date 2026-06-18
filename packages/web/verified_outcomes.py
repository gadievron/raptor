"""Adapters from web scanner findings into RAPTOR VerifiedOutcome records."""

from __future__ import annotations

from typing import Iterable, Optional

from core.verified_outcome.types import Oracle, OutcomeStatus, VerifiedOutcome
from packages.web.models import WebFinding


def from_web_finding(
    finding: WebFinding,
    *,
    authorization: str = "operator_authorized_live_web_scan",
) -> Optional[VerifiedOutcome]:
    """Map a confirmed live HTTP finding into the shared oracle record."""

    data = finding.to_dict()
    if data.get("oracle") != "web" or not data.get("confirmed"):
        return None

    evidence = {
        "target_url": data.get("target_url") or data.get("url"),
        "url": data.get("url"),
        "method": data.get("method"),
        "title": data.get("title"),
        "finding_evidence": data.get("evidence"),
        "payload": data.get("confirmation_payload"),
        "response_evidence": data.get("response_evidence"),
        "baseline_evidence": data.get("baseline_evidence"),
        "attack_evidence": data.get("attack_evidence"),
        "diff_summary": data.get("diff_summary"),
        "attack_vector": data.get("attack_vector"),
        "auth_context": data.get("auth_context"),
        "check_id": data.get("check_id"),
        "asvs_category": data.get("asvs_category"),
    }

    return VerifiedOutcome(
        finding_id=data.get("finding_id") or data["id"],
        oracle=Oracle.WEB,
        status=OutcomeStatus.VERIFIED,
        reproducible=False,
        evidence={k: v for k, v in evidence.items() if v is not None},
        cwe_id=data.get("cwe_id"),
        file=data.get("target_url") or data.get("url"),
        produced_by="raptor-web",
        authorization=authorization,
    )


def verified_outcomes_for_findings(
    findings: Iterable[WebFinding],
    *,
    authorization: str = "operator_authorized_live_web_scan",
) -> list[VerifiedOutcome]:
    outcomes = [
        outcome
        for finding in findings
        if (outcome := from_web_finding(finding, authorization=authorization))
    ]
    return outcomes
