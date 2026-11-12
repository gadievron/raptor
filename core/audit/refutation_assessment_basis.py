"""Retain historically admitted scoped refutations in review history.

The producer must already have admitted all enumerated claims through the
existing refutation validator. Serialising or reading these records neither
repeats that admission nor certifies checker semantics, current source
freshness, build correspondence, or whole-function safety.
"""
from __future__ import annotations

import json
from typing import Any

from .knowledge_requests import KnowledgeOrigin
from .review_claims import MAX_HISTORY_CLAIMS, read_history
from .verification_results import ClaimRefutation, ProbeOutcome, _non_refuting_probe

_RECORD_KEYS = frozenset(("action", "file", "function", "line_start", "hypothesis",
                          "source_identity", "checks"))
_OPTIONAL_RECORD_KEYS = frozenset(("claim_reference", "material_admission"))
_CHECK_KEYS = frozenset(("tool", "verdict", "rule_id", "reason"))


def _text(value: object, *, empty: bool = False) -> bool:
    if not isinstance(value, str) or (not empty and not value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _checks(value: object) -> list[dict[str, str]] | None:
    if not isinstance(value, list) or not value:
        return None
    projected = []
    for check in value:
        if (not isinstance(check, dict) or set(check) != _CHECK_KEYS
                or any(not _text(check.get(key), empty=key == "reason") for key in _CHECK_KEYS)
                or check["verdict"] != "refuted"):
            return None
        # This rejects existing diagnostic/non-refuting rule namespaces.
        # It does not reconstruct a live receipt or establish tool semantics.
        if _non_refuting_probe(ProbeOutcome(**check)):
            return None
        projected.append({key: check[key] for key in ("tool", "verdict", "rule_id", "reason")})
    return projected


def _known_metadata(record: dict) -> bool:
    reference = record.get("claim_reference")
    if "claim_reference" in record and (
            not isinstance(reference, dict) or set(reference) != {"claim_id", "revision_id"}
            or any(not _text(value) for value in reference.values())):
        return False
    material = record.get("material_admission")
    if "material_admission" in record and (
            not isinstance(material, dict)
            or set(material) != {"default_cwe", "declared_material", "role"}
            or not _text(material.get("default_cwe"), empty=True)
            or material.get("role") != "rejection_context_not_checker_scope"
            or not isinstance(material.get("declared_material"), list)
            or any(not _text(value, empty=True) for value in material["declared_material"])):
        return False
    return True


def read_refutation_basis(review: dict) -> dict[str, Any] | None:
    """Project exact historical subjects/checks without granting authority.

    The caller validates the enclosing pass, terminal status and assessment
    kind. Original optional receipt metadata remains durable but is not copied
    into this descriptive projection.
    """
    from .assessment_basis import _bound_review

    # Reuse the existing history's byte and JSON bounds for direct callers too.
    bounded = read_history({"version": 1, "role": "review-history-only", "review": review,
                            "intakes": [], "complete": False, "omissions": []})
    bound = _bound_review(bounded.get("review")) if bounded is not None else None
    if bound is None:
        return None
    origin = bound["origin"]
    hypotheses = bound.get("assessment_hypotheses")
    records = bound.get("assessment_refutations")
    if (not isinstance(hypotheses, list) or not 0 < len(hypotheses) <= MAX_HISTORY_CLAIMS
            or any(not _text(subject) for subject in hypotheses)
            or len(set(hypotheses)) != len(hypotheses)
            or not isinstance(records, list) or not 0 < len(records) <= MAX_HISTORY_CLAIMS):
        return None
    projected = []
    covered = set()
    seen = set()
    subject_metadata: dict[str, tuple[Any, Any]] = {}
    for record in records:
        if (not isinstance(record, dict) or not _RECORD_KEYS <= set(record)
                or not set(record) <= _RECORD_KEYS | _OPTIONAL_RECORD_KEYS
                or record.get("action") != "claim_refutation"
                or (record.get("file"), record.get("function"), record.get("line_start"))
                != (origin["file"], origin["function"], origin["line_start"])
                or type(record.get("line_start")) is not int
                or record.get("source_identity") != origin["source_identity"]
                or not _text(record.get("hypothesis")) or record["hypothesis"] not in hypotheses):
            return None
        if not _known_metadata(record):
            return None
        recorded_origin = {**origin, "source_identity": record["source_identity"]}
        if _bound_review({"attempt_id": bound["attempt_id"], "origin": recorded_origin}) is None:
            return None
        checks = _checks(record.get("checks"))
        if checks is None:
            return None
        # Conflicting or duplicated snapshots cannot be resolved by arrival
        # order. Multiple distinct admitted checks remain separate records.
        identity = json.dumps(record, sort_keys=True, allow_nan=False)
        if identity in seen:
            return None
        seen.add(identity)
        subject = record["hypothesis"]
        metadata = (record.get("claim_reference"), record.get("material_admission"))
        if subject in subject_metadata and subject_metadata[subject] != metadata:
            return None
        subject_metadata[subject] = metadata
        covered.add(record["hypothesis"])
        projected.append({"hypothesis": record["hypothesis"], "checks": checks})
    if covered != set(hypotheses):
        return None
    return {"hypotheses": hypotheses, "records": projected}


def record_refutation_basis(
    value: object, *, origin: KnowledgeOrigin, attempt_id: str,
    hypotheses: list[str], receipts: tuple[ClaimRefutation, ...] | list[ClaimRefutation],
) -> dict[str, Any] | None:
    """Snapshot already admitted receipts against their exact review binding.

    This function does not decide whether the claims are refuted. Its caller
    owns that decision and must retain unknown assumptions and other concerns.
    """
    from .assessment_basis import record_assessment_basis

    if (not isinstance(origin, KnowledgeOrigin) or not isinstance(hypotheses, list)
            or not 0 < len(hypotheses) <= MAX_HISTORY_CLAIMS
            or any(not _text(subject) for subject in hypotheses)
            or len(set(hypotheses)) != len(hypotheses)
            or not isinstance(receipts, (tuple, list)) or not 0 < len(receipts) <= MAX_HISTORY_CLAIMS):
        return None
    history = record_assessment_basis(value, origin=origin, attempt_id=attempt_id,
        status="clean", basis="enumerated_claims_refuted")
    if history is None:
        return None
    records = []
    for receipt in receipts:
        if not isinstance(receipt, ClaimRefutation):
            return None
        try:
            record = receipt.to_record()
            # Check shape before matches() consults potentially malformed
            # historical rule fields. Cancellation is never swallowed here.
            if not isinstance(record, dict) or _checks(record.get("checks")) is None or not any(receipt.matches(
                file=origin.file, function=origin.function, line_start=origin.line_start,
                hypothesis=subject, source_identity=origin.source_identity,
            ) for subject in hypotheses):
                return None
            records.append(record)
        except (TypeError, ValueError, OverflowError, RecursionError):
            return None
    try:
        subjects = json.loads(json.dumps(hypotheses, allow_nan=False))
        snapshots = json.loads(json.dumps(records, allow_nan=False))
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None
    review = history["review"]
    if ("assessment_hypotheses" in review or "assessment_refutations" in review) and (
            review.get("assessment_hypotheses") != subjects or review.get("assessment_refutations") != snapshots):
        return None
    review["assessment_hypotheses"] = subjects
    review["assessment_refutations"] = snapshots
    bounded = read_history(history)
    if bounded is None or read_refutation_basis(bounded["review"]) is None:
        return None
    return bounded
