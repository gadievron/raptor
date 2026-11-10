"""Bounded review/claim history, never verification or verdict authority.

Only the live IHV intake issues revisions. Decoding this format returns data,
not ClaimRevision objects, receipts, source freshness or bug coverage.
"""

from copy import deepcopy
from dataclasses import asdict
import json
from typing import Any

from .claims import ClaimRevision
from .knowledge_requests import KnowledgeOrigin

MAX_HISTORY_BYTES = 64 * 1024
MAX_HISTORY_CLAIMS = 64
MAX_HISTORY_INTAKES = 8
_ROLE = "review-history-only"


def _size(value: object) -> int:
    return len(json.dumps(value, ensure_ascii=True, allow_nan=False).encode("utf-8"))


def read_history(value: object) -> dict[str, Any] | None:
    """Copy a bounded history envelope; no live identity is reconstructed."""
    if not isinstance(value, dict) or (type(value.get("version")) is not int or value.get("version") != 1) or value.get("role") != _ROLE:
        return None
    try:
        if _size(value) > MAX_HISTORY_BYTES:
            return None
        # A JSON round trip prevents borrowed objects or tuples escaping into
        # the durable format and rejects non-serialisable producer values.
        copied = json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None
    if (not isinstance(copied.get("intakes"), list)
            or len(copied["intakes"]) > MAX_HISTORY_INTAKES
            or not isinstance(copied.get("omissions"), list)
            or type(copied.get("complete")) is not bool):
        return None
    if _size(copied.get("review")) > MAX_HISTORY_BYTES // 4 or _size(copied["omissions"]) > 2048:
        return None
    count = 0
    for intake in copied["intakes"]:
        if not isinstance(intake, dict) or not isinstance(intake.get("claims"), list):
            return None
        if _size(intake.get("review")) > MAX_HISTORY_BYTES // 4:
            return None
        count += len(intake["claims"])
        if count > MAX_HISTORY_CLAIMS:
            return None
        for claim in intake["claims"]:
            if (not isinstance(claim, dict) or not isinstance(claim.get("reference"), dict)
                    or not isinstance(claim.get("hypothesis"), dict)):
                return None
    return copied


def begin_review(origin: KnowledgeOrigin, attempt_id: str) -> dict[str, Any]:
    """Retain the pre-call source observation even when IHV never runs."""
    history: dict[str, Any] = {"version": 1, "role": _ROLE, "review": {
        "attempt_id": attempt_id, "origin": asdict(origin)},
        "intakes": [], "complete": False, "omissions": ["not-intaken"]}
    if _size(history) > MAX_HISTORY_BYTES // 4:
        history["review"] = None
        history["omissions"].append("review-origin-byte-limit")
    return history


def record_intake(value: object, revisions: list[ClaimRevision]) -> dict[str, Any]:
    """Snapshot the exact live IHV revisions without creating another ID set.

    Complete means this intake's candidates were retained, not that the
    review found every bug or that any candidate was verified.
    """
    previous = read_history(value)
    history: dict[str, Any] = {"version": 1, "role": _ROLE,
        "review": previous.get("review") if previous else None,
        "intakes": [{"claims": [], "candidate_count": len(revisions), "omitted_count": 0}],
        "complete": True, "omissions": []}
    review = history["review"]
    origin = review.get("origin") if isinstance(review, dict) else None
    occurrence = (origin.get("file"), origin.get("function"), origin.get("line_start")) if isinstance(origin, dict) else None
    if not revisions or any(occurrence != (r.file, r.function, r.line_start) for r in revisions):
        history["review"] = None
        history["omissions"].append("review-origin-unavailable")
        history["complete"] = False
    elif not isinstance(origin, dict) or not origin.get("source_identity"):
        history["omissions"].append("review-source-unavailable")
        history["complete"] = False
    intake = history["intakes"][0]
    for revision in revisions:
        row = {"reference": revision.reference(), "hypothesis": revision.hypothesis}
        try:
            admitted = len(intake["claims"]) < MAX_HISTORY_CLAIMS and _size(row) < MAX_HISTORY_BYTES // 2
            if admitted:
                intake["claims"].append(row)
                if _size(history) <= MAX_HISTORY_BYTES - 512:
                    continue
                intake["claims"].pop()
        except (TypeError, ValueError, OverflowError, RecursionError):
            pass
        intake["omitted_count"] += 1
    if intake["omitted_count"]:
        history["complete"] = False
        history["omissions"].append("candidate-limit-or-unserialisable")
    return history


def merge_history(prior: object, fresh: object) -> dict[str, Any] | None:
    """Retain contributing attempts without attributing new text to old IDs."""
    left, right = read_history(prior), read_history(fresh)
    if left is None and right is None:
        return None
    histories = [history for history in (left, right) if history is not None]
    result: dict[str, Any] = {"version": 1, "role": _ROLE, "review": None,
                              "intakes": [], "complete": False,
                              "omissions": ["merged-candidate-projection-unmapped"]}
    # All producer omission reasons are fixed strings. Keep them distinct so
    # repeated merges cannot grow the envelope through repeated warnings.
    for history in histories:
        for reason in history["omissions"]:
            if isinstance(reason, str) and reason not in result["omissions"]:
                result["omissions"].append(reason)
        intakes = history["intakes"] or [{"claims": [], "candidate_count": None, "omitted_count": 0}]
        for intake in intakes:
            item = deepcopy(intake)
            item.setdefault("review", history.get("review"))
            result["intakes"].append(item)
            if read_history(result) is None:
                result["intakes"].pop()
                if "contributor-limit" not in result["omissions"]:
                    result["omissions"].append("contributor-limit")
    return result



def prompt_history(value: object, *, max_bytes: int = 8192) -> str:
    """Render whole retained statements, disclosing prompt-budget omissions."""
    history = read_history(value)
    if history is None:
        return "Prior claim identities unavailable; do not infer identity from similar prose."
    omitted = 0
    original_claims = [intake.pop("claims") for intake in history["intakes"]]
    for intake in history["intakes"]:
        intake["claims"] = []
    for intake, claims in zip(history["intakes"], original_claims):
        kept = intake["claims"]
        for claim in claims:
            kept.append(claim)
            if _size(history) > max_bytes - 256:
                kept.pop()
                omitted += 1
    if omitted:
        history["complete"] = False
        history["omissions"].append({"reason": "prompt-byte-limit", "count": omitted})
    if _size(history) > max_bytes:
        return "Prior claim history omitted: metadata exceeds the prompt byte limit."
    return json.dumps(history, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
