"""Deterministic claim adjudication; this module never executes a checker.

Contracts and admission contexts are pipeline inputs, never model-authored
fields. The publication adapter deliberately gives legacy labels no authority.
"""
from collections import defaultdict
from dataclasses import dataclass
from typing import Literal

from .refutation_source import SourceIdentity

POLICY_VERSION = "claim-adjudication-v1"
SHADOW_FILENAME = "claim-adjudication-shadow.json"


@dataclass(frozen=True)
class ClaimContract:
    """A registered adapter's whole-claim obligations, not proposed proof text."""
    adapter: str
    version: str
    obligations: frozenset[str]
    negative_obligations: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ClaimContext:
    claim_id: str
    revision_id: str
    source: SourceIdentity
    contract: str
    dependencies: tuple[str, ...]
    assumptions: tuple[str, ...]
    occurrence: tuple[str, str, int]
    parent_revision_id: str | None = None


@dataclass(frozen=True)
class FactEvent:
    event_id: str
    context: ClaimContext
    obligation: str
    adapter: str
    contract_version: str
    execution: str
    semantic: str
    request_id: str
    executed_request_id: str
    complete: bool
    raw_reference: str


@dataclass(frozen=True)
class ClaimChange:
    event_id: str
    claim_id: str
    revision_id: str
    kind: Literal["withdrawn", "invalidated", "superseded"]
    context: ClaimContext | None = None
    reason: str = ""
    evidence_reference: str = ""
    target_event_ids: frozenset[str] = frozenset()
    successor: ClaimContext | None = None


def _unique(events):
    """Quarantine every variant of an ambiguous ID, independent of order."""
    grouped = defaultdict(set)
    for event in events:
        grouped[event.event_id].add(event)
    admitted, quarantined = [], []
    for event_id in sorted(grouped):
        variants = grouped[event_id]
        if not event_id or len(variants) != 1:
            quarantined.append(event_id)
        else:
            admitted.append(next(iter(variants)))
    return admitted, quarantined


def reduce_claims(contexts, events, *, contracts, changes=(), unadmitted_claims=(),
                  policy_version=POLICY_VERSION):
    """Reduce admitted typed facts against explicit current contexts.

    SourceIdentity is a bounded file identity, not a dependency closure; callers
    must supply the current dependency and assumption bindings separately.
    Unknown execution, silence and model receipt labels cannot discharge facts.
    """
    original_events = [*events, *changes]
    events, quarantine = _unique(original_events)
    ambiguous_claims = {
        (event.claim_id, event.revision_id) if isinstance(event, ClaimChange)
        else (event.context.claim_id, event.context.revision_id)
        for event in original_events if event.event_id in quarantine
    }
    definitions = defaultdict(set)
    for context in contexts:
        definitions[(context.claim_id, context.revision_id)].add(context)
    rows = []
    for key in sorted(definitions):
        variants = definitions[key]
        row = {"claim_id": key[0], "revision_id": key[1], "state": "unresolved",
               "supported_obligations": [], "contradicted_obligations": [],
               "accepted_event_ids": [], "rejected_event_ids": [], "missing_obligations": []}
        if len(variants) != 1:
            row["reason"] = "conflicting_current_context"
            rows.append(row)
            continue
        context = next(iter(variants))
        contract = contracts.get(context.contract)
        if (not isinstance(contract, ClaimContract) or not contract.obligations
                or not contract.negative_obligations <= contract.obligations
                or not contract.adapter or not contract.version):
            row["reason"] = "registered_whole_claim_contract_unavailable"
            rows.append(row)
            continue
        supported, contradicted, lifecycle = set(), set(), set()
        bound_changes = []
        invalidated = set()
        facts_by_id = {event.event_id: event for event in events if isinstance(event, FactEvent)}
        for change in events:
            if not isinstance(change, ClaimChange) or (change.claim_id, change.revision_id) != key:
                continue
            grounded = (change.context == context and bool(change.evidence_reference.strip()))
            valid = False
            if grounded and change.kind == "withdrawn":
                valid = (change.reason == "unsupported_theory_withdrawal"
                         and not change.target_event_ids and change.successor is None)
            elif grounded and change.kind == "invalidated":
                valid = (change.reason in {"source_changed", "dependencies_changed", "assumptions_changed",
                                           "adapter_contract_revoked", "evidence_integrity_rejected"}
                         and bool(change.target_event_ids) and change.successor is None
                         and all(event_id in facts_by_id and facts_by_id[event_id].context == context
                                 for event_id in change.target_event_ids))
                if valid:
                    invalidated.update(change.target_event_ids)
            elif grounded and change.kind == "superseded":
                successor = change.successor
                valid = (change.reason == "explicit_claim_revision" and not change.target_event_ids
                         and successor is not None and successor.claim_id == context.claim_id
                         and successor.revision_id != context.revision_id
                         and successor.parent_revision_id == context.revision_id
                         and successor.occurrence == context.occurrence
                         and definitions.get((successor.claim_id, successor.revision_id)) == {successor})
            if valid:
                bound_changes.append(change)
            else:
                row["rejected_event_ids"].append(change.event_id)
        for event in events:
            if isinstance(event, ClaimChange):
                continue
            if (event.context.claim_id, event.context.revision_id) != key:
                continue
            admitted = (event.event_id not in invalidated
                        and event.context == context and event.adapter == contract.adapter
                        and event.contract_version == contract.version
                        and event.obligation in contract.obligations
                        and event.execution == "completed" and event.complete is True
                        and bool(event.request_id) and event.request_id == event.executed_request_id
                        and bool(event.raw_reference))
            positive = admitted and event.semantic == "supports_fact"
            negative = (admitted and event.semantic == "contradicts_fact"
                        and event.obligation in contract.negative_obligations)
            if positive or negative:
                row["accepted_event_ids"].append(event.event_id)
                (supported if positive else contradicted).add(event.obligation)
            else:
                row["rejected_event_ids"].append(event.event_id)
        row["supported_obligations"] = sorted(supported)
        row["contradicted_obligations"] = sorted(contradicted)
        row["missing_obligations"] = sorted(contract.obligations - supported)
        for change in bound_changes:
            # A model's abandonment of a theory cannot erase admitted facts,
            # including partial support or a scoped mechanical contradiction.
            if change.kind == "withdrawn" and (supported or contradicted):
                row["rejected_event_ids"].append(change.event_id)
            else:
                lifecycle.add(change.kind)
                row["accepted_event_ids"].append(change.event_id)
        if "superseded" in lifecycle:
            row["state"] = "superseded"
        elif supported & contradicted:
            row["state"] = "conflicted"
        elif contradicted:
            row["state"] = "refuted"
        elif not row["missing_obligations"]:
            row["state"] = "supported"
        elif "withdrawn" in lifecycle:
            row["state"] = "withdrawn"
        if lifecycle:
            row["reason"] = "lifecycle_" + "+".join(sorted(lifecycle))
        row["accepted_event_ids"].sort()
        row["rejected_event_ids"].sort()
        if key in ambiguous_claims:
            row["state"] = "unresolved"
            row["reason"] = "conflicting_event_identity"
        rows.append(row)
    for claim_id, revision_id in sorted(set(unadmitted_claims) - set(definitions)):
        rows.append({"claim_id": claim_id, "revision_id": revision_id, "state": "unresolved",
                     "reason": "registered_whole_claim_contract_and_current_admission_unavailable",
                     "supported_obligations": [], "contradicted_obligations": [],
                     "accepted_event_ids": [], "rejected_event_ids": [], "missing_obligations": []})
    rows.sort(key=lambda row: (row["claim_id"], row["revision_id"]))
    return {"policy_version": policy_version, "claims": rows,
            "quarantined_event_ids": quarantine}


def publication_shadow(claim_index, findings):
    """Observe the real publisher without upgrading legacy observations.

    Existing traces lack a registered whole-claim request/result contract and
    export-time current source/dependency admission. Preserve that gap instead
    of translating a strong receipt or model boolean into mechanical support.
    """
    indexed = claim_index.get("claims", [])
    reduced = reduce_claims([], [], contracts={}, unadmitted_claims=[
        (claim["claim_reference"]["claim_id"], claim["claim_reference"]["revision_id"])
        for claim in indexed])
    states = {(row["claim_id"], row["revision_id"]): row for row in reduced["claims"]}
    claims = []
    for claim in indexed:
        definition = claim["definition"]
        legacy = [f for f in findings if
                  (f.get("file"), f.get("function"), f.get("line")) ==
                  (definition["file"], definition["function"], definition["line_start"])]
        claims.append({**states[(claim["claim_reference"]["claim_id"], claim["claim_reference"]["revision_id"])],
                       "producer_check_ids": claim["producer_check_ids"],
                       "legacy_correspondence": "location_only_not_claim_authority",
                       "legacy_projections": [{"status": f.get("status"), "confidence": f.get("confidence")}
                                              for f in legacy]})
    return {"schema_version": 1, "policy_version": POLICY_VERSION, "mode": "shadow",
            "authoritative": False, "history_complete": False, "claims": claims,
            "unmatched_legacy_findings": len(findings) if not claims else None,
            "limitations": ["Legacy public statuses and confidence are unchanged.",
                            "Legacy receipt labels and model proposals have no adjudication authority.",
                            "Missing contract or current source/dependency admission remains unresolved."],
            "claim_index_quarantine": claim_index.get("quarantined_revisions", [])}
