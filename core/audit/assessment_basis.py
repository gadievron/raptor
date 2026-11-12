"""Record a review's descriptive basis without granting evidence authority.

The caller owns the completed model invocation or admitted withdrawal/refutation.
These helpers bind its record to the existing review history; they do not prove
that event occurred, validate current source, or establish mechanical assurance.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Literal

from .knowledge_requests import KnowledgeOrigin
from .review_claims import read_history

AssessmentBasis = Literal["model_judgment", "model_judgment_withdrawal", "enumerated_claims_refuted"]
_BASES = frozenset(("model_judgment", "model_judgment_withdrawal", "enumerated_claims_refuted"))
_CLEAN_BASES = frozenset(("model_judgment_withdrawal", "enumerated_claims_refuted"))
_STATUSES = frozenset(("clean", "suspicious", "finding", "dormant", "dark"))


def _text(value: object, limit: int) -> bool:
    if not isinstance(value, str) or not value or len(value) > limit:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _bound_review(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not _text(value.get("attempt_id"), 128):
        return None
    origin = value.get("origin")
    if (not isinstance(origin, dict) or set(origin) != {
            "pass_id", "file", "function", "line_start", "line_end", "source_identity"}):
        return None
    if (not _text(origin.get("pass_id"), 128) or not _text(origin.get("file"), 4096)
            or not _text(origin.get("function"), 512)
            or type(origin.get("line_start")) is not int or origin["line_start"] < 1
            or type(origin.get("line_end")) is not int or origin["line_end"] < origin["line_start"]):
        return None
    source = origin.get("source_identity")
    if not isinstance(source, dict) or set(source) != {"sha256", "version"}:
        return None
    digest, version = source.get("sha256"), source.get("version")
    if (not isinstance(digest, str) or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            or not isinstance(version, list) or len(version) != 5
            or any(type(part) is not int for part in version)):
        return None
    return value


def _same_review(left: dict, right: dict) -> bool:
    return (left["attempt_id"], left["origin"]) == (right["attempt_id"], right["origin"])


def _single_review(history: dict) -> dict[str, Any] | None:
    review = _bound_review(history.get("review"))
    if review is None:
        return None
    for intake in history["intakes"]:
        contributor = intake.get("review")
        if contributor is not None:
            bound = _bound_review(contributor)
            if bound is None or not _same_review(bound, review):
                return None
            if any(field in bound and bound[field] != review.get(field)
                   for field in ("assessment_basis", "assessment_status",
                                 "assessment_hypotheses", "assessment_refutations")):
                return None
    return review


def record_assessment_basis(
    value: object, *, origin: KnowledgeOrigin, attempt_id: str, status: str,
    basis: AssessmentBasis = "model_judgment",
) -> dict[str, Any] | None:
    """Copy a pipeline-issued basis onto its exact existing review record.

    Call only after the actual producer completes or the existing withdrawal
    or scoped-refutation validator accepts. Shape checks do not authenticate a model
    response or a caller-supplied admission flag. Error/unknown callbacks and
    histories without a single bound source observation stay unavailable.
    """
    if (not isinstance(origin, KnowledgeOrigin) or not isinstance(basis, str) or basis not in _BASES
            or not isinstance(status, str) or status not in _STATUSES
            or basis in _CLEAN_BASES and status != "clean"):
        return None
    history = read_history(value)
    if history is None:
        return None
    review = _single_review(history)
    if review is None:
        return None
    expected = asdict(origin)
    source = expected.get("source_identity")
    if isinstance(source, dict) and isinstance(source.get("version"), tuple):
        source["version"] = list(source["version"])
    if review["origin"] != expected or review["attempt_id"] != attempt_id:
        return None
    previous = history.get("assessment_basis")
    if "assessment_basis" in review or "assessment_status" in review:
        old_basis, old_status = review.get("assessment_basis"), review.get("assessment_status")
        if (not isinstance(old_basis, str) or old_basis not in _BASES
                or not isinstance(old_status, str) or old_status not in _STATUSES or old_status != status
                or old_basis != basis and not (
                    old_basis == "model_judgment" and basis in _CLEAN_BASES and status == "clean")):
            return None
    if (previous is not None and (not isinstance(previous, str) or previous not in _BASES)
            or previous in _CLEAN_BASES and basis != previous):
        return None
    history["assessment_basis"] = basis
    review["assessment_basis"] = basis
    review["assessment_status"] = status
    return read_history(history)


def read_assessment_basis(value: object, *, pass_id: str, status: str) -> dict[str, Any] | None:
    """Project recorded historical basis for one selected pass and status.

    A saved label, including an admitted-withdrawal label, is historical data.
    This projection supplies neither current freshness nor evidence authority.
    Mixed assessments cannot borrow a contributor's basis for the whole result.
    """
    history = read_history(value)
    if history is None:
        return None
    review = _single_review(history)
    if review is None:
        return None
    basis = review.get("assessment_basis")
    if (not isinstance(basis, str) or basis not in _BASES
            or not _text(pass_id, 128)
            or history.get("assessment_basis") != basis
            or not isinstance(status, str) or status not in _STATUSES
            or review.get("assessment_status") != status
            or review["origin"]["pass_id"] != pass_id
            or basis in _CLEAN_BASES and status != "clean"):
        return None
    result: dict[str, Any] = {"basis": basis, "status": status, "pass_id": pass_id,
              "attempt_id": review["attempt_id"], "origin": review["origin"],
              "scope": "historical_review_only"}
    if basis == "enumerated_claims_refuted":
        from .refutation_assessment_basis import read_refutation_basis
        refutations = read_refutation_basis(review)
        if refutations is None:
            return None
        result["refutations"] = refutations
    elif "assessment_hypotheses" in review or "assessment_refutations" in review:
        return None
    return result
