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
_STATE_ORDER = ("candidate", "unresolved", "supported", "refuted", "conflicted", "withdrawn", "superseded")
_STATES = frozenset(_STATE_ORDER)


def load_claim_presentation(out_dir: Path) -> dict | None:
    path = out_dir / _SHADOW_FILE
    unavailable = {"mode": "unavailable", "authoritative": False, "artifact": _SHADOW_FILE}
    if not path.exists() and not path.is_symlink():
        return {**unavailable, "artifact": None}
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
    state_counts = dict.fromkeys(_STATE_ORDER, 0)
    for claim in claims:
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
        state_counts[state] += 1
        if len(rows) >= _MAX_ROWS:
            continue
        # Preserve only supplied dimensions; supported/confirmed text
        # cannot fill in an absent assessment basis or assurance grade.
        rows.append({"claim_id": claim_id, "revision_id": revision_id, "state": state,
                     "reason": reason,
                     "missing_obligations": missing[:20], "obligations_omitted": max(0, len(missing) - 20)})
    return {"mode": "shadow", "authoritative": False, "artifact": _SHADOW_FILE,
            "policy_version": policy, "claim_count": len(claims), "claims": rows,
            "state_counts": state_counts,
            "claims_omitted": max(0, len(claims) - len(rows))}


def claim_presentation_blocks(report: dict) -> list[Block]:
    record = report.get("claim_adjudication")
    if not isinstance(record, dict):
        return []
    if record.get("mode") != "shadow":
        return [Block("paragraph", title="Claim adjudication unavailable",
                      text="The saved shadow projection is unavailable; legacy assessments are unchanged.")]
    bases = report.get("assessment_bases")
    basis_notice = ("Reviewer basis is recorded separately; this shadow does not establish claim assurance. "
                    if isinstance(bases, dict) and type(bases.get("recorded")) is int and bases["recorded"] > 0 else
                    "Assessment basis and assurance grade were not recorded; both remain unavailable. ")
    children = [Block("paragraph", text=(
        "Shadow comparison only. These states do not replace legacy assessments or establish mechanical verification. "
        + basis_notice + "Clean means no current finding was established in the completed review's scope, never proved safe. "
        "Error, skipped and deferred work describe processing or coverage, not safety conclusions."))]
    counts = record.get("state_counts")
    if (isinstance(counts, dict) and set(counts) == _STATES
            and all(type(counts[state]) is int and counts[state] >= 0 for state in _STATE_ORDER)
            and sum(counts.values()) == record["claim_count"]):
        children.append(Block("table", title="Recorded claim states", columns=["Shadow state", "Recorded rows"],
                              rows=[[state, str(counts[state])] for state in _STATE_ORDER]))
    else:
        children.append(Block("paragraph", text=(
            "Recorded claim-state totals are unavailable in this saved report; "
            "displayed rows do not establish totals for omitted rows.")))
    children.append(Block("table", columns=["Claim", "Revision", "Shadow state", "Recorded limitations"],
                          rows=[[row["claim_id"], row["revision_id"], row["state"],
                                 _limitation(row)] for row in record["claims"]]))
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
