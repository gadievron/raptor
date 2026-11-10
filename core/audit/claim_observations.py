"""Read-only correspondence index over authenticated observation envelopes.

This does not admit evidence or decide claim status. Callers authenticate and
quarantine event identities first. Revision conflicts are a separate boundary.
"""

from collections import defaultdict
from copy import deepcopy
from hashlib import sha256
from uuid import UUID

from core.json import dumps_canonical


def _uuid(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return value if UUID(value).hex == value else None
    except ValueError:
        return None


def _definition(reference, hypothesis) -> bool:
    if not isinstance(reference, dict) or not isinstance(hypothesis, dict):
        return False
    if not _uuid(reference.get("claim_id")) or not _uuid(reference.get("revision_id")):
        return False
    revision = reference.get("revision")
    parent = reference.get("parent_revision")
    if type(revision) is not int or revision < 1:
        return False
    if revision == 1:
        if parent is not None:
            return False
    elif not _uuid(parent) or parent == reference["revision_id"]:
        return False
    return (all(isinstance(reference.get(key), str) and reference[key].strip()
                for key in ("pass_id", "file", "function"))
            and type(reference.get("line_start")) is int and reference["line_start"] >= 0
            and isinstance(hypothesis.get("mechanism"), str) and bool(hypothesis["mechanism"].strip()))


def _refs(values):
    return [{"event_id": event_id, "index": index} for event_id, index in sorted(values)]


def index_claim_observations(claim_events, checks) -> dict:
    """Index fixed revisions and exact producer links, without adjudication.

    A differing immutable definition under one revision UUID quarantines every
    variant. Receipt labels, source bindings and proposed refutations remain
    observations, not part of the immutable statement. Source freshness is not
    revalidated. Statements stay in the raw events rather than being copied.
    """
    definitions: dict[str, dict[bytes, dict]] = defaultdict(dict)
    occurrences: dict[str, set[tuple[str, int]]] = defaultdict(set)
    invalid_revisions: set[str] = set()
    unavailable: list[dict] = []
    for event in claim_events:
        event_id = event.get("id")
        snapshot = event.get("observations")
        data = snapshot.get("data") if isinstance(snapshot, dict) and snapshot.get("complete") is True else None
        details = data.get("details") if isinstance(data, dict) else None
        lineage = event.get("claim_revisions")
        if not isinstance(event_id, str) or not event_id.strip():
            unavailable.append({"event_id": event_id, "reason": "event_identity_unavailable"})
            continue
        if not isinstance(details, list):
            unavailable.append({"event_id": event_id, "reason": "statement_payload_unavailable"})
            continue
        if (event.get("claim_revisions_complete") is not True or not isinstance(lineage, list)
                or len(lineage) != len(details) or event.get("observation_count") != len(details)):
            unavailable.append({"event_id": event_id, "reason": "lineage_unavailable"})
            continue
        for index, (observation, reference) in enumerate(zip(details, lineage)):
            hypothesis = observation.get("hypothesis") if isinstance(observation, dict) else None
            revision_id = _uuid(reference.get("revision_id")) if isinstance(reference, dict) else None
            if revision_id is not None:
                occurrences[revision_id].add((event_id, index))
            if not isinstance(hypothesis, dict) or not _definition(reference, hypothesis):
                unavailable.append({"event_id": event_id, "index": index, "reason": "invalid_revision_definition"})
                if revision_id is not None:
                    invalid_revisions.add(revision_id)
                continue
            fingerprint = sha256(dumps_canonical({"definition": reference, "hypothesis": hypothesis}).encode("utf-8")).digest()
            definitions[reference["revision_id"]][fingerprint] = {
                "definition": deepcopy(reference), "mechanism": hypothesis["mechanism"],
            }

    claims: list[dict] = []
    quarantine: list[dict] = []
    admitted: dict[str, dict] = {}
    for revision_id in sorted(occurrences):
        variants = definitions.get(revision_id, {})
        if len(variants) != 1 or revision_id in invalid_revisions:
            quarantine.append({"revision_id": revision_id, "reason": "conflicting_or_invalid_definition",
                               "observations": _refs(occurrences[revision_id])})
            continue
        variant = next(iter(variants.values()))
        reference = variant["definition"]
        refs = _refs(occurrences[revision_id])
        row = {"claim_reference": {"claim_id": reference["claim_id"], "revision_id": revision_id},
               "definition": reference, "statement_reference": dict(refs[0]),
               "observations": refs, "producer_check_ids": [], "adjudication": "unadjudicated"}
        claims.append(row)
        admitted[revision_id] = {"claim": row, "scope": (
            reference["file"], reference["function"], reference["line_start"], variant["mechanism"])}

    rejected: list[dict] = []
    links: dict[str, set[str]] = defaultdict(set)
    for check in checks:
        check_id = check.get("id")
        reference = check.get("claim_reference")
        if not isinstance(check_id, str) or not check_id.strip():
            continue
        if (not isinstance(reference, dict) or not _uuid(reference.get("claim_id"))
                or not _uuid(reference.get("revision_id"))):
            rejected.append({"check_id": check_id, "reason": "lineage_unavailable"})
            continue
        target = admitted.get(reference["revision_id"])
        if target is None or target["claim"]["claim_reference"] != reference:
            rejected.append({"check_id": check_id, "reason": "revision_unavailable_or_mismatched"})
            continue
        scope = check.get("scope")
        if (not isinstance(scope, dict) or type(scope.get("line_start")) is not int
                or (scope.get("file"), scope.get("function"), scope.get("line_start"), scope.get("hypothesis"))
                != target["scope"]):
            rejected.append({"check_id": check_id, "reason": "producer_scope_mismatch"})
            continue
        links[reference["revision_id"]].add(check_id)
    for claim in claims:
        claim["producer_check_ids"] = sorted(links[claim["claim_reference"]["revision_id"]])
    return {"claims": claims, "quarantined_revisions": quarantine,
            "unavailable_inputs": sorted(unavailable, key=dumps_canonical),
            "rejected_check_links": sorted(rejected, key=dumps_canonical)}
