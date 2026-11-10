"""Validate explicit model withdrawal proposals against supplied material.

Acceptance means the reviewer referenced the delivered claim and source. It
is not a proof that its explanation is true, a mechanical refutation, or
permission to replace a verdict. The caller owns source freshness, prior
support, scope mapping and acknowledged publication.
"""

from collections import Counter
import json
from typing import Any

from core.source.lines import split_lines

from .claim_observations import _definition, _uuid

MAX_PROPOSALS = 32
MAX_DELIVERED_CLAIMS = 64
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_ANCHORS = 8


def _json(value: object) -> str | None:
    # Check a conservative character/node budget before serialising. A giant
    # reason, nested array or cycle must not buy an unbounded temporary string.
    remaining = MAX_PAYLOAD_BYTES
    active: set[int] = set()

    def bounded(item: object, depth: int) -> bool:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 32:
            return False
        if isinstance(item, str):
            remaining -= len(item)
            return remaining >= 0
        if item is None or type(item) in (bool, float):
            return True
        if type(item) is int:
            return item.bit_length() <= MAX_PAYLOAD_BYTES
        if not isinstance(item, (dict, list, tuple)) or id(item) in active or len(item) > remaining:
            return False
        active.add(id(item))
        try:
            if isinstance(item, dict):
                return all(isinstance(key, str) and bounded(key, depth + 1) and bounded(val, depth + 1)
                           for key, val in item.items())
            return all(bounded(val, depth + 1) for val in item)
        finally:
            active.remove(id(item))

    if not bounded(value, 0):
        return None
    try:
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=True,
                             allow_nan=False, separators=(",", ":"))
        return encoded if len(encoded) <= MAX_PAYLOAD_BYTES else None
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None


def _definitions(rows: object, occurrence: tuple[str, str, int]) -> dict[str, dict]:
    """Coalesce exact repeats; quarantine every conflicting/invalid variant."""
    if not isinstance(rows, list) or len(rows) > MAX_DELIVERED_CLAIMS or _json(rows) is None:
        return {}
    variants: dict[str, dict[str, dict]] = {}
    invalid: set[str] = set()
    for row in rows:
        reference = row.get("reference") if isinstance(row, dict) else None
        hypothesis = row.get("hypothesis") if isinstance(row, dict) else None
        revision_id = _uuid(reference.get("revision_id")) if isinstance(reference, dict) else None
        if revision_id is None:
            continue
        if (not isinstance(reference, dict) or not isinstance(hypothesis, dict)
                or not _definition(reference, hypothesis)
                or (reference["file"], reference["function"], reference["line_start"]) != occurrence):
            invalid.add(revision_id)
            continue
        encoded = _json({"reference": reference, "hypothesis": hypothesis})
        if encoded is None:
            invalid.add(revision_id)
            continue
        variants.setdefault(revision_id, {})[encoded] = json.loads(encoded)
    return {revision_id: next(iter(values.values()))
            for revision_id, values in variants.items()
            if len(values) == 1 and revision_id not in invalid}


def _source_available(fragment: object, occurrence: tuple[str, str, int]) -> bool:
    if not isinstance(fragment, dict) or not _uuid(fragment.get("fragment_id")):
        return False
    start, end, source = fragment.get("line_start"), fragment.get("line_end"), fragment.get("source")
    if (type(start) is not int or type(end) is not int or start < 1 or end < start
            or (fragment.get("file"), fragment.get("function"), start) != occurrence
            or not isinstance(source, str) or not source or len(source) > MAX_PAYLOAD_BYTES):
        return False
    try:
        if len(source.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            return False
    except UnicodeError:
        return False
    return len(split_lines(source)) == end - start + 1


def _bounded_proposal_text(value: object, limit: int) -> str | None:
    if not isinstance(value, str) or len(value) > limit or not value.strip():
        return None
    return value.strip()


def _anchors(value: object, fragment: dict) -> list[dict] | None:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ANCHORS:
        return None
    anchors = []
    for anchor in value:
        if not isinstance(anchor, dict) or anchor.get("fragment_id") != fragment["fragment_id"]:
            return None
        start, end = anchor.get("line_start"), anchor.get("line_end")
        if (type(start) is not int or type(end) is not int
                or not fragment["line_start"] <= start <= end <= fragment["line_end"]):
            return None
        anchors.append({"fragment_id": fragment["fragment_id"], "line_start": start, "line_end": end})
    return anchors


def evaluate_withdrawals(
    proposals: object, *, delivered_claims: list[dict], source_fragment: dict | None,
    file: str, function: str, line_start: int,
) -> dict[str, Any]:
    """Return bounded decisions without changing claims, evidence or status.

    Only the caller's actually delivered, complete current-function source
    fragment may satisfy an anchor. No file named by a model is read here.
    Missing proposals withdraw nothing; duplicate revision IDs reject every
    proposal for that ID, including otherwise-identical duplicates.
    """
    result: dict[str, Any] = {"accepted": [], "rejected": []}
    if proposals is None:
        return result
    if not isinstance(proposals, list):
        result["rejected"].append({"index": None, "reason": "malformed_proposals"})
        return result
    if len(proposals) > MAX_PROPOSALS or _json(proposals) is None:
        result["rejected"].append({"index": None, "reason": "proposal_payload_limit", "count": len(proposals)})
        return result
    occurrence = (file, function, line_start)
    definitions = _definitions(delivered_claims, occurrence)
    source_ok = type(line_start) is int and line_start >= 1 and _source_available(source_fragment, occurrence)
    counts = Counter(p.get("revision_id") for p in proposals
                     if isinstance(p, dict) and _uuid(p.get("revision_id")))
    for index, proposal in enumerate(proposals):
        reason = None
        if not isinstance(proposal, dict):
            reason = "malformed_proposal"
        else:
            revision_id = _uuid(proposal.get("revision_id"))
            claim_id = _uuid(proposal.get("claim_id"))
            definition = definitions.get(revision_id) if revision_id else None
            if not revision_id or not claim_id:
                reason = "invalid_claim_reference"
            elif counts[revision_id] != 1:
                reason = "duplicate_revision_proposal"
            elif definition is None or definition["reference"]["claim_id"] != claim_id:
                reason = "claim_definition_unavailable"
            elif not source_ok:
                reason = "source_fragment_unavailable"
            elif proposal.get("remaining_unknowns") != []:
                reason = "remaining_unknowns"
            else:
                corrected = _bounded_proposal_text(proposal.get("corrected_premise"), 1024)
                explanation = _bounded_proposal_text(proposal.get("reason"), 2048)
                # source_ok establishes the real dictionary shape above.
                anchors = (_anchors(proposal.get("source_anchors"), source_fragment)
                           if isinstance(source_fragment, dict) else None)
                if corrected is None or explanation is None:
                    reason = "missing_or_oversized_explanation"
                elif anchors is None:
                    reason = "source_anchor_unavailable"
                else:
                    accepted = {**definition, "corrected_premise": corrected, "reason": explanation,
                                "source_anchors": anchors, "adjudication": "model_withdrawn"}
                    result["accepted"].append(accepted)
                    encoded = _json(result)
                    # Reserve bounded room for every later rejection record.
                    if encoded is not None and len(encoded) <= MAX_PAYLOAD_BYTES - MAX_PROPOSALS * 128:
                        continue
                    result["accepted"].pop()
                    reason = "decision_payload_limit"
        result["rejected"].append({"index": index, "reason": reason})
    return result
