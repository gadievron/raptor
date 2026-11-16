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
    rows: list[dict[str, object]] = []
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
            "claims_omitted": max(0, len(claims) - len(rows)),
            "conditional_evidence": _conditional_evidence(payload, rows)}


def _conditional_evidence(payload: dict, rows: list[dict]) -> dict:
    """Project saved availability, never re-admit evidence or establish freshness."""
    availability = payload.get("preparation_availability", [])
    unavailable = {"state": "unavailable", "records": []}
    if not isinstance(availability, list):
        return unavailable
    records: list[dict] = []
    # Only an exact displayed claim/revision can receive a recorded conclusion.
    indexed = {(row["claim_id"], row["revision_id"]): row for row in rows}
    for item in availability:
        if not isinstance(item, dict):
            return unavailable
        signature = item.get("requested_conclusion")
        if signature is None:
            continue
        reference = item.get("claim_reference")
        if not isinstance(reference, dict):
            return unavailable
        key = (reference.get("claim_id"), reference.get("revision_id"))
        if any(not isinstance(value, str) for value in key):
            return unavailable
        if key not in indexed:
            continue
        if (not isinstance(signature, dict)
                or set(signature) != {"statement", "conclusion_kind", "effect_scope", "conditions"}
                or any(not isinstance(signature.get(field), str) or not signature[field]
                       or len(signature[field]) > 2048
                       for field in ("statement", "conclusion_kind", "effect_scope"))
                or not isinstance(signature["conditions"], list)
                or not 1 <= len(signature["conditions"]) <= 32
                or any(not isinstance(value, str) or not value or len(value) > 1024
                       for value in signature["conditions"])
                or item.get("assessment") != "shadow-only"
                or item.get("authoritative") is not False
                or item.get("issuer_cwe_verified") is not False
                or item.get("effect_scope") != signature["effect_scope"]
                or not isinstance(item.get("reason"), str) or len(item["reason"]) > 500):
            return unavailable
        if key in {(record["claim_id"], record["revision_id"]) for record in records}:
            return unavailable
        records.append({"claim_id": key[0], "revision_id": key[1],
                        "conclusion": signature, "publication_reason": item["reason"],
                        "authoritative": False, "issuer_cwe_verified": False})
    return {"state": "recorded", "records": records}


def _conditional_blocks(record: dict) -> list[Block]:
    evidence = record.get("conditional_evidence")
    if not isinstance(evidence, dict):
        return []
    if evidence.get("state") != "recorded":
        return [Block("paragraph", title="Conditional evidence unavailable",
                      text="The saved conditional details could not be read; claim states and legacy assessments are unchanged.")]
    records = evidence.get("records", [])
    if not records:
        return []
    children = [Block("paragraph", text=(
        "Recorded source-model implications under the listed assumptions. "
        "Publication reasons describe the saved run; this report does not revalidate current source or retained evidence. "
        "These records do not establish target behaviour, CWE correctness or a confirmed vulnerability."))]
    for item in records:
        signature = item["conclusion"]
        children.append(Block("section", title="Conditional claim " + item["claim_id"], children=[
            Block("paragraph", text=signature["statement"]),
            Block("table", columns=["Recorded attribute", "Value"], rows=[
                ["Revision", item["revision_id"]], ["Publication", item["publication_reason"]],
                ["Conclusion kind", signature["conclusion_kind"]], ["Scope", signature["effect_scope"]]]),
            Block("table", title="Required assumptions (not established target facts)",
                  columns=["Condition"], rows=[[value] for value in signature["conditions"]]),
        ]))
    return [Block("section", title="Conditional evidence (recorded; not authoritative)", children=children)]


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
    return [Block("section", title="Claim adjudication (shadow; not authoritative)", children=children),
            *_conditional_blocks(record)]


def _limitation(row: dict) -> str:
    parts = [row["reason"].replace("_", " ")] if row["reason"] else []
    if row["missing_obligations"]:
        parts.append("Missing obligations: " + ", ".join(row["missing_obligations"]))
    if row["obligations_omitted"]:
        parts.append(f"{row['obligations_omitted']} further obligations retained in the linked shadow")
    return "; ".join(parts) or "No limitation recorded; this does not certify completeness"
