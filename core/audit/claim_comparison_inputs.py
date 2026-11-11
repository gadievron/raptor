"""Historical identity joins for manual shadow migration review, never adjudication."""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import logging
from pathlib import Path
import re

from core.json import dumps_canonical, loads, save_json
from core.source import open_regular_beneath
from core.source.streams import preserving_stream_error
from .claim_observations import _definition, _uuid
from .review_claims import read_history

logger = logging.getLogger(__name__)
FILENAME = "claim-comparison-inputs.json"
ROLE = "historical_claim_comparison_not_adjudication"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_ROWS = 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")
_STATES = {"candidate", "unresolved", "supported", "refuted", "conflicted", "withdrawn", "superseded"}


def _unavailable(reason):
    return {"role": ROLE, "status": "unavailable", "reason": reason,
            "authoritative": False, "source_revalidated_at_export": False}


def historical_claim_link(history_value, finding):
    """Select one complete, unmapped-free historical intake by exact definition.

    Runtime review and IHV intake identifiers are distinct. Neither is a provider
    execution identity or a fresh source/dependency admission.
    """
    history = read_history(history_value)
    if history is None or history.get("complete") is not True or history["omissions"]:
        return _unavailable("complete_history_unavailable")
    review = history.get("review")
    origin = review.get("origin") if isinstance(review, dict) else None
    if not isinstance(origin, dict):
        return _unavailable("review_origin_unavailable")
    occurrence = (finding.get("file"), finding.get("function"), finding.get("line"))
    source = origin.get("source_identity")
    source_hash = source.get("sha256") if isinstance(source, dict) else None
    if (type(finding.get("line")) is not int
            or occurrence != (origin.get("file"), origin.get("function"), origin.get("line_start"))
            or not isinstance(source_hash, str) or _DIGEST.fullmatch(source_hash) is None
            or any(not isinstance(value, str) or not value.strip() or len(value) > 512
                   for value in (origin.get("pass_id"), review.get("attempt_id")))):
        return _unavailable("review_origin_mismatch_or_unavailable")
    intakes = history["intakes"]
    if len(intakes) != 1:
        return _unavailable("intake_association_unavailable")
    intake = intakes[0]
    claims = intake["claims"]
    if (type(intake.get("candidate_count")) is not int or intake["candidate_count"] != len(claims)
            or type(intake.get("omitted_count")) is not int or intake["omitted_count"] != 0
            or ("review" in intake and intake["review"] != review)):
        return _unavailable("intake_incomplete_or_unmapped")
    variants = defaultdict(dict)
    invalid = set()
    for row in claims:
        reference, hypothesis = row["reference"], row["hypothesis"]
        revision_id = reference.get("revision_id")
        if not _definition(reference, hypothesis):
            invalid.add(revision_id if isinstance(revision_id, str) else "")
            continue
        digest = sha256(dumps_canonical({"definition": reference, "hypothesis": hypothesis}).encode("utf-8")).hexdigest()
        variants[revision_id][digest] = row
    # Scan the complete history before selecting the final statement. A changed
    # definition elsewhere in this intake cannot be hidden by the final filter.
    if invalid or any(len(values) != 1 for values in variants.values()):
        return _unavailable("invalid_or_conflicting_history")
    matching = []
    for values in variants.values():
        digest, row = next(iter(values.items()))
        reference = row["reference"]
        if ((reference["file"], reference["function"], reference["line_start"]) == occurrence
                and row["hypothesis"]["mechanism"] == finding.get("hypothesis")):
            matching.append((digest, reference))
    if len(matching) != 1:
        return _unavailable("ambiguous_final_claim" if matching else "final_claim_unavailable")
    digest, reference = matching[0]
    if len(reference["pass_id"]) > 512:
        return _unavailable("intake_identity_unavailable")
    return {"role": ROLE, "status": "recorded", "authoritative": False,
            "claim_reference": {"claim_id": reference["claim_id"], "revision_id": reference["revision_id"]},
            "definition_sha256": digest, "review_pass_id": origin["pass_id"],
            "review_attempt_id": review["attempt_id"], "intake_pass_id": reference["pass_id"],
            "historical_source_sha256": source_hash, "source_revalidated_at_export": False}


def _key(row):
    reference = row.get("claim_reference") if isinstance(row, dict) else None
    if not isinstance(reference, dict):
        return None
    claim, revision = reference.get("claim_id"), reference.get("revision_id")
    return (claim, revision) if _uuid(claim) and _uuid(revision) else None


def _unique_rows(rows, *, shadow=False):
    variants = defaultdict(dict)
    invalid = set()
    if not isinstance(rows, list):
        raise ValueError("comparison rows unavailable")
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("comparison row unavailable")
        reference = row if shadow else row.get("claim_reference")
        if not isinstance(reference, dict):
            raise ValueError("comparison identity unavailable")
        claim, revision = reference.get("claim_id"), reference.get("revision_id")
        if not _uuid(revision):
            raise ValueError("comparison revision unavailable")
        if not _uuid(claim):
            invalid.add(revision)
            continue
        # Revision UUID ownership is global, as in the observation index. A
        # second claim owner or malformed variant cannot leave a valid winner.
        variants[revision][dumps_canonical(row)] = row
    result = {}
    for revision, values in variants.items():
        if revision in invalid or len(values) != 1:
            continue
        row = next(iter(values.values()))
        key = (row["claim_id"], revision) if shadow else _key(row)
        result[key] = row
    return result


def comparison_inputs(export, claim_index, shadow):
    """Produce review pairs without defining status equivalence or severity."""
    indexed = _unique_rows(claim_index.get("claims"))
    reduced = _unique_rows(shadow.get("claims"), shadow=True)
    records = []
    for index, finding in enumerate(export.get("findings", [])):
        trace = finding.get("verification_trace") if isinstance(finding, dict) else None
        records.append(("findings", index, trace, finding))
    for index, trace in enumerate(export.get("clean_review_traces", [])):
        records.append(("clean_review_traces", index, trace, {"status": trace.get("final_status")}
                        if isinstance(trace, dict) else {}))
    pairs, unavailable = [], []
    for collection, index, trace, legacy in records[:MAX_ROWS]:
        pointer = {"collection": collection, "index": index}
        link = trace.get("claim_lineage") if isinstance(trace, dict) else None
        key = _key(link)
        reason = "historical_lineage_unavailable"
        if (isinstance(link, dict) and link.get("role") == ROLE and link.get("status") == "recorded"
                and link.get("authoritative") is False and link.get("source_revalidated_at_export") is False
                and key is not None):
            indexed_row, reduced_row = indexed.get(key), reduced.get(key)
            digest = link.get("definition_sha256")
            if indexed_row is None:
                reason = "indexed_definition_unavailable_or_ambiguous"
            elif (not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None
                  or digest != indexed_row.get("definition_sha256")):
                reason = "definition_digest_mismatch_or_unavailable"
            elif (reduced_row is None or not isinstance(reduced_row.get("state"), str)
                  or reduced_row["state"] not in _STATES):
                reason = "shadow_state_unavailable_or_ambiguous"
            elif (not isinstance(legacy, dict) or not isinstance(legacy.get("status"), str)
                  or legacy["status"] not in {"finding", "suspicious", "dark", "clean", "error"}):
                reason = "legacy_status_unavailable"
            else:
                pairs.append({"legacy_pointer": pointer, "claim_reference": dict(link["claim_reference"]),
                              "definition_sha256": digest,
                              "legacy_status": legacy["status"],
                              "legacy_confidence": legacy.get("confidence")
                              if isinstance(legacy.get("confidence"), str)
                              and legacy["confidence"] in {"low", "medium", "high"} else None,
                              "shadow_state": reduced_row["state"], "review_status": "manual_review_required",
                              "current_context_correspondence": "not_evaluated", "authoritative": False})
                continue
        unavailable.append({"legacy_pointer": pointer, "reason": reason})
    return {"schema_version": 1, "role": ROLE, "authoritative": False,
            "history_complete": False, "policy_version": shadow.get("policy_version"),
            "pairs": pairs, "unavailable": unavailable,
            "observed_legacy_records": len(records), "omitted_legacy_records": max(0, len(records) - MAX_ROWS),
            "limitations": ["Pairs identify historical definitions for manual migration review, not semantic equivalence.",
                            "Legacy assessments, confidence and reducer authority are unchanged.",
                            "Review, intake and provider execution identities are distinct.",
                            "Current source, build, dependencies and applicability are not revalidated.",
                            "Input byte hashes identify compared bytes; they do not authenticate artifacts."]}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate comparison input field")
        result[key] = value
    return result


def _read_input(out_dir, filename):
    stream = open_regular_beneath(out_dir, filename, "rb")
    if stream is None:
        raise ValueError("complete comparison input unavailable")
    with preserving_stream_error(stream):
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("complete comparison input unavailable")
    value = loads(raw, max_bytes=MAX_INPUT_BYTES, object_pairs_hook=_unique_object)
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("comparison input schema unavailable")
    return value, {"sha256": sha256(raw).hexdigest(), "bytes": len(raw)}


def write_comparison_inputs(export, out_dir):
    """Require this publisher's successful inputs; never revive stale files."""
    from .check_trace import CLAIM_OBSERVATIONS_FILENAME
    from .claim_adjudication import POLICY_VERSION, SHADOW_FILENAME

    unavailable = {"artifact": FILENAME, "status": "unavailable", "role": ROLE, "authoritative": False}
    summary = export.get("verification_summary")
    observations = summary.get("claim_observations") if isinstance(summary, dict) else None
    projection = export.get("claim_adjudication_shadow")
    if (not isinstance(observations, dict) or observations.get("status") != "recorded"
            or observations.get("artifact") != CLAIM_OBSERVATIONS_FILENAME
            or observations.get("role") != "unadjudicated_observation"
            or not isinstance(projection, dict) or projection.get("artifact") != SHADOW_FILENAME
            or projection.get("mode") != "shadow" or projection.get("authoritative") is not False
            or projection.get("policy_version") != POLICY_VERSION or projection.get("status") not in (None, "recorded")):
        return unavailable
    try:
        observed, observed_hash = _read_input(out_dir, CLAIM_OBSERVATIONS_FILENAME)
        shadow, shadow_hash = _read_input(out_dir, SHADOW_FILENAME)
        if (observed.get("role") != "unadjudicated_observation" or shadow.get("mode") != "shadow"
                or observed.get("history_complete") is not False or shadow.get("history_complete") is not False
                or shadow.get("authoritative") is not False or shadow.get("policy_version") != POLICY_VERSION
                or not isinstance(observed.get("claim_index"), dict)):
            return unavailable
        payload = comparison_inputs(export, observed["claim_index"], shadow)
        payload["inputs"] = {CLAIM_OBSERVATIONS_FILENAME: observed_hash, SHADOW_FILENAME: shadow_hash}
        save_json(Path(out_dir) / FILENAME, payload)
        return {"artifact": FILENAME, "status": "recorded", "role": ROLE, "authoritative": False,
                "pairs": len(payload["pairs"]), "unavailable": len(payload["unavailable"]),
                "omitted": payload["omitted_legacy_records"]}
    except Exception:
        logger.warning("could not retain claim comparison inputs", exc_info=True)
        return unavailable
