"""LabeledAttempt production for /web oracle-verified findings.

Adapter lives here in ``packages/web/`` rather than in
``core/labeled_attempts/`` so the dependency arrow points the right
way (packages depend on core, not vice versa) — same reasoning as
``packages/fuzzing/witness_adapter.py``.

Records are written for verified AND control-refuted outcomes so both
directions surface in ``libexec/raptor-verified-outcomes``; findings
whose verification stayed inconclusive produce an ``uncertain`` record
(kept out of the verified view, still corpus signal). The finding
itself is never dropped from the scan report — verification only adds
evidence tiers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, TYPE_CHECKING
from urllib.parse import urlparse

from core.labeled_attempts.store import write as store_write
from core.labeled_attempts.types import (
    LabeledAttempt,
    WebEvidence,
    compute_finding_signature,
)
from core.logging import get_logger
from core.security.redaction import redact_secrets
from packages.web.oracle import REFUTED, VERIFIED, VerificationResult

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger()

CWE_BY_VULN_TYPE = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "ssti": "CWE-1336",
    "command_injection": "CWE-78",
    "path_traversal": "CWE-22",
    "ssrf": "CWE-918",
}

_OUTCOME_BY_STATUS: dict[str, Literal["success", "reasoned_failure", "uncertain"]] = {
    VERIFIED: "success",
    REFUTED: "reasoned_failure",
    # inconclusive (flaky replay / transport errors / mixed controls)
    # → the producer does not commit either way.
}


def build_web_attempt(
    *,
    url: str,
    param: str,
    payload: str,
    vuln_type: str,
    method: str,
    result: VerificationResult,
    reveal_secrets: bool = False,
) -> LabeledAttempt:
    """One heuristic finding + its verification → a LabeledAttempt."""
    cwe = CWE_BY_VULN_TYPE.get(vuln_type, "CWE-20")
    parsed = urlparse(url)
    signature = compute_finding_signature(
        cwe=cwe,
        file_path=parsed.path or "/",
        function=param,
        line=0,
        vuln_type=vuln_type,
    )
    safe_url = redact_secrets(url, reveal_secrets=reveal_secrets)
    response_evidence: dict[str, Any] = dict(result.observations)
    response_evidence["verification_status"] = result.status
    response_evidence["reason"] = result.reason
    if result.refuted_by_control:
        # The flag the verified-outcomes projection gates REFUTED on:
        # only a positive control experiment may set it.
        response_evidence["refuted_by_control"] = True

    evidence = WebEvidence(
        target_url=safe_url,
        http_request={
            "method": method.upper(),
            "url": safe_url,
            "param": param,
            "payload": payload,
        },
        response_evidence=response_evidence,
        evidence_type=result.evidence_type,
        timestamp_iso=datetime.now(timezone.utc).isoformat(),
    )
    return LabeledAttempt(
        finding_id=f"web:{vuln_type}:{parsed.path or '/'}:{param}",
        finding_signature=signature,
        cwe=cwe,
        outcome=_OUTCOME_BY_STATUS.get(result.status, "uncertain"),
        web_evidence=evidence,
        producing_model="web-oracle",
        tools_used=("web-oracle",),
        reproducible=False,  # live-HTTP point-in-time
    )


def build_attempt_from_confirmed_finding(
    finding: Any,
    *,
    reveal_secrets: bool = False,
) -> LabeledAttempt | None:
    """A three-gate-confirmed WebFinding → a LabeledAttempt, or None.

    The gate is the same oracle-proof rule the VerifiedOutcome adapter
    applies (packages.web.verified_outcomes.has_exploit_oracle_evidence):
    only findings carrying the full payload/response/oracle chain enter
    the labeled-attempts pool — a passive check marked "confirmed" never
    does. outcome is "success" by construction, since the three-gate
    oracle already required baseline/attack differential evidence.
    """
    from packages.web.verified_outcomes import has_exploit_oracle_evidence

    data = finding.to_dict()
    if data.get("oracle") != "web" or not data.get("confirmed"):
        return None
    if not has_exploit_oracle_evidence(data):
        return None

    vuln_type = str(data.get("vuln_type") or "")
    cwe = str(data.get("cwe_id") or CWE_BY_VULN_TYPE.get(vuln_type, "CWE-20"))
    target = str(data.get("target_url") or data.get("url") or "")
    parsed = urlparse(target)
    params = list(data.get("affected_parameters") or [])
    param = params[0] if params else "-"
    signature = compute_finding_signature(
        cwe=cwe,
        file_path=parsed.path or "/",
        function=param,
        line=0,
        vuln_type=vuln_type,
    )
    safe_url = redact_secrets(target, reveal_secrets=reveal_secrets)
    response_evidence: dict[str, Any] = {
        "verification_status": "verified",
        "oracle_signal": data.get("oracle_signal"),
        "response_evidence": data.get("response_evidence"),
        "baseline_evidence": data.get("baseline_evidence"),
        "attack_evidence": data.get("attack_evidence"),
        "diff_summary": data.get("diff_summary"),
        "affected_parameters": params,
        "reason": "three-gate oracle: baseline/attack differential with class signal",
    }

    evidence = WebEvidence(
        target_url=safe_url,
        http_request={
            "method": str(data.get("method") or "GET").upper(),
            "url": safe_url,
            "param": param,
            "payload": str(data.get("confirmation_payload") or ""),
        },
        response_evidence={
            k: v for k, v in response_evidence.items() if v is not None
        },
        evidence_type=str(data.get("oracle_signal") or "web").partition(":")[0],
        timestamp_iso=datetime.now(timezone.utc).isoformat(),
    )
    return LabeledAttempt(
        finding_id=str(data.get("finding_id") or data.get("id") or ""),
        finding_signature=signature,
        cwe=cwe,
        outcome="success",
        web_evidence=evidence,
        producing_model="raptor-web",
        tools_used=("web-three-gate-oracle",),
        reproducible=False,  # live-HTTP point-in-time
    )


def write_web_attempts(
    attempts: list[LabeledAttempt], out_dir: Path,
) -> list[Path]:
    """Persist records to the run's per-project pool; never raises."""
    written: list[Path] = []
    for attempt in attempts:
        try:
            written.extend(store_write(attempt, project_dir=out_dir))
        except Exception:
            logger.debug("labeled-attempt write failed", exc_info=True)
    return written
