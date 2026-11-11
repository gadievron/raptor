"""Additive public presentation of the recorded claim adjudication shadow.

The shadow never selects public verdicts, establishes freshness or grants
mechanical assurance. Legacy output remains the assessment during migration.
"""
from __future__ import annotations

from pathlib import Path

from core.json import load_json
from core.reporting.document import Block

_SHADOW_FILE = "claim-adjudication-shadow.json"
_MAX_BYTES = 8 * 1024 * 1024
_MAX_ROWS = 100
_STATES = frozenset({"candidate", "unresolved", "supported", "refuted", "conflicted", "withdrawn", "superseded"})


def load_claim_presentation(out_dir: Path) -> dict | None:
    path = out_dir / _SHADOW_FILE
    if not path.exists() and not path.is_symlink():
        return None
    unavailable = {"mode": "unavailable", "authoritative": False, "artifact": _SHADOW_FILE}
    payload = load_json(path, max_bytes=_MAX_BYTES)
    if (not isinstance(payload, dict) or type(payload.get("schema_version")) is not int
            or payload["schema_version"] != 1 or payload.get("mode") != "shadow"
            or payload.get("authoritative") is not False):
        return unavailable
    policy = payload.get("policy_version")
    claims = payload.get("claims")
    if not isinstance(policy, str) or not policy or len(policy) > 128 or not isinstance(claims, list):
        return unavailable
    rows = []
    for claim in claims[:_MAX_ROWS]:
        if not isinstance(claim, dict):
            return unavailable
        claim_id, revision_id, state = (claim.get(key) for key in ("claim_id", "revision_id", "state"))
        if (not isinstance(claim_id, str) or not claim_id or len(claim_id) > 128
                or not isinstance(revision_id, str) or not revision_id or len(revision_id) > 128
                or not isinstance(state, str) or state not in _STATES):
            return unavailable
        reason = claim.get("reason", "")
        missing = claim.get("missing_obligations", [])
        if (not isinstance(reason, str) or len(reason) > 500 or not isinstance(missing, list)
                or any(not isinstance(item, str) or len(item) > 128 for item in missing)):
            return unavailable
        # The supplied publisher does not provide either dimension. In
        # particular, supported/confirmed text cannot fill in assurance.
        rows.append({"claim_id": claim_id, "revision_id": revision_id, "state": state,
                     "assessment_basis": None, "assurance": None, "reason": reason,
                     "missing_obligations": missing[:20], "obligations_omitted": max(0, len(missing) - 20)})
    return {"mode": "shadow", "authoritative": False, "artifact": _SHADOW_FILE,
            "policy_version": policy, "claim_count": len(claims), "claims": rows,
            "claims_omitted": max(0, len(claims) - len(rows))}


def claim_presentation_blocks(report: dict) -> list[Block]:
    record = report.get("claim_adjudication")
    if not isinstance(record, dict):
        return []
    if record.get("mode") != "shadow":
        return [Block("paragraph", title="Claim adjudication unavailable",
                      text="The saved shadow projection is unavailable; legacy assessments are unchanged.")]
    children = [Block("paragraph", text=(
        "Shadow comparison only. These states do not replace legacy assessments or establish mechanical verification. "
        "Assessment basis and assurance grade were not recorded; both remain unavailable. "
        "Clean means no current finding was established in the completed review's scope, never proved safe. "
        "Error, skipped and deferred work describe processing or coverage, not safety conclusions.")),
        Block("table", columns=["Claim", "Revision", "Shadow state", "Assessment basis", "Assurance", "Recorded limitations"],
              rows=[[row["claim_id"], row["revision_id"], row["state"], "Unavailable", "Unavailable",
                     _limitation(row)] for row in record["claims"]])]
    if record["claims_omitted"]:
        children.append(Block("paragraph", text=f"Showing {len(record['claims'])} of {record['claim_count']} claims; complete recorded shadow remains in {_SHADOW_FILE}."))
    children.append(Block("paragraph", text=f"Recorded policy: {record['policy_version']}. See {_SHADOW_FILE} for retained provenance and limitations."))
    return [Block("section", title="Claim adjudication (shadow; not authoritative)", children=children)]


def _limitation(row: dict) -> str:
    parts = [row["reason"].replace("_", " ")] if row["reason"] else []
    if row["missing_obligations"]:
        parts.append("Missing obligations: " + ", ".join(row["missing_obligations"]))
    if row["obligations_omitted"]:
        parts.append(f"{row['obligations_omitted']} further obligations retained in the linked shadow")
    return "; ".join(parts) or "No limitation recorded; this does not certify completeness"
