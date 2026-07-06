"""Evidence ledger for web scans."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from packages.web.models import WebFinding


def build_web_evidence_ledger(
    *,
    findings: Iterable[WebFinding],
    request_history: Iterable[dict[str, Any]],
    external_validation: Iterable[dict[str, Any]],
    execution_policy: dict[str, Any],
) -> dict[str, Any]:
    """Return a compact, operator-readable evidence record for one scan."""

    finding_list = list(findings)
    request_list = list(request_history)
    validators = list(external_validation)
    by_target: dict[str, list[dict[str, Any]]] = {}
    for result in validators:
        target = result.get("target_url")
        if target:
            by_target.setdefault(str(target), []).append(result)

    records = []
    for finding in finding_list:
        data = finding.to_dict()
        target_url = data.get("target_url") or data.get("url")
        proof_chain = []
        if data.get("baseline_evidence"):
            proof_chain.append({
                "kind": "baseline_response",
                "content": data["baseline_evidence"],
            })
        if data.get("attack_evidence"):
            proof_chain.append({
                "kind": "attack_response",
                "content": data["attack_evidence"],
            })
        if data.get("diff_summary"):
            proof_chain.append({
                "kind": "response_diff",
                "content": data["diff_summary"],
            })
        if data.get("oracle_signal"):
            proof_chain.append({
                "kind": "oracle_signal",
                "content": data["oracle_signal"],
            })
        if not proof_chain and data.get("evidence"):
            proof_chain.append({
                "kind": "check_observation",
                "content": data["evidence"],
            })

        records.append({
            "finding_id": data["finding_id"],
            "title": data["title"],
            "status": data["status"],
            "severity": data["severity"],
            "target_url": target_url,
            "method": data.get("method"),
            "affected_parameters": data.get("affected_parameters", []),
            "confirmation_payload": data.get("confirmation_payload"),
            "proof_chain": proof_chain,
            "external_validation": by_target.get(str(target_url), []),
            "replay": {
                "method": data.get("method"),
                "url": target_url,
                "parameters": data.get("affected_parameters", []),
                "payload": data.get("confirmation_payload"),
                "note": "Live target replay requires fresh operator authorisation.",
            } if data.get("confirmation_payload") else None,
        })

    validator_status = Counter(
        str(result.get("status", "unknown")) for result in validators
    )
    return {
        "summary": {
            "finding_count": len(records),
            "confirmed_web_oracle_findings": sum(
                1 for finding in finding_list
                if finding.to_dict().get("confirmed") and finding.oracle == "web"
            ),
            "external_validator_runs": len(validators),
            "external_validator_status": dict(validator_status),
            "request_history_entries": len(request_list),
        },
        "execution_policy": execution_policy,
        "findings": records,
    }
