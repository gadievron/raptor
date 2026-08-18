"""Domain model for semantic concept learning.

Dataclasses for concepts, invariants, contracts, and the composite
domain model.  Serialise to / from ``domain-model.json``.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def _filter_fields(cls: type, raw: dict) -> dict:
    """Keep only keys that are valid dataclass fields for *cls*."""
    valid = {f.name for f in dataclasses.fields(cls)}
    return {k: v for k, v in raw.items() if k in valid}


# ------------------------------------------------------------------
# Evidence
# ------------------------------------------------------------------

@dataclass
class Evidence:
    type: str  # type_definition | api_pattern | code_path | doc | test
    file: str
    observation: str
    line: int | None = None
    item: str | None = None
    hash: str | None = None
    # Verbatim source quote supporting the observation (receipt raw
    # material; verified by core.concepts.receipts.verify_receipt).
    quote: str | None = None


# ------------------------------------------------------------------
# Concept
# ------------------------------------------------------------------

CONFIDENCE_GRADES = ("inferred", "observed", "traced", "corroborated", "documented", "tested")

LIFECYCLE_STATES = (
    "discovered",
    "proposed",
    "qualified",
    "validated",
    "compiled",
    "producing",
    "stale",
)


@dataclass
class Concept:
    id: str
    description: str
    evidence: list[Evidence] = field(default_factory=list)
    confidence: str = "inferred"
    state: str = "proposed"
    derived_version: str | None = None
    qualified_by: list[str] = field(default_factory=list)
    derived_from: list[dict[str, Any]] = field(default_factory=list)
    # Provenance tier (core.concepts.receipts): verbatim | mechanical
    # | llm_summarized | llm_prior. Empty = pre-tier legacy entry —
    # treated as non-actionable by tier-gated consumers.
    provenance: str = ""
    receipt: dict[str, Any] | None = None


# ------------------------------------------------------------------
# Invariant
# ------------------------------------------------------------------

@dataclass
class Invariant:
    id: str
    concept: str
    statement: str
    negation: str
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    counter_examples_checked: list[str] = field(default_factory=list)
    confidence: str = "inferred"
    mechanical_rule: str | None = None
    relevant_cwes: list[str] = field(default_factory=list)
    provenance: str = ""
    receipt: dict[str, Any] | None = None


# ------------------------------------------------------------------
# Contract
# ------------------------------------------------------------------

@dataclass
class Contract:
    function: str
    file: str
    when: str = ""
    input_semantics: str = ""
    output_semantics: str = ""
    ownership_transfer: str = ""
    implication: str = ""
    security_note: str = ""
    hash: str | None = None
    provenance: str = ""
    receipt: dict[str, Any] | None = None


# ------------------------------------------------------------------
# Study item (Phase 1 → Phase 2 handoff)
# ------------------------------------------------------------------

@dataclass
class StudyItem:
    """One work unit produced by raptor-study-prep for a Phase 2 agent."""

    id: str
    kind: str  # struct | function | paired_ops | flag_enum | macro
    name: str
    file: str
    line: int | None = None
    definition: str = ""
    fields: list[str] = field(default_factory=list)
    paired_with: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    doc_comment: str = ""
    refcount_fields: list[str] = field(default_factory=list)
    related_items: list[str] = field(default_factory=list)
    lock_sites: list[str] = field(default_factory=list)
    rcu_usage: list[str] = field(default_factory=list)
    ordering_annotations: list[str] = field(default_factory=list)
    bounds_guards: list[str] = field(default_factory=list)
    error_gotos: list[str] = field(default_factory=list)
    owned_types: list[str] = field(default_factory=list)
    clamping_patterns: list[str] = field(default_factory=list)
    flexible_arrays: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    flag_checks: list[str] = field(default_factory=list)
    alloc_frees: list[str] = field(default_factory=list)
    resource_lifecycle: list[str] = field(default_factory=list)
    state_transitions: list[str] = field(default_factory=list)
    gate_checks: list[str] = field(default_factory=list)
    dispatch_tables: list[str] = field(default_factory=list)
    null_guards: list[str] = field(default_factory=list)
    validation_bounds: list[str] = field(default_factory=list)
    relevance_tier: int | None = None
    usage_class: str | None = None  # writer | reader | passthru
    # Mechanically detected doc/code disagreement (code wins) — see
    # core.concepts.receipts.detect_stale_doc.
    stale_doc: str = ""


# ------------------------------------------------------------------
# Security context (target privilege / attack surface)
# ------------------------------------------------------------------

@dataclass
class SecurityContext:
    privilege_level: str = ""  # kernel | root_daemon | user_service | sandboxed
    attack_surface: str = ""  # local_socket | network | filesystem | ipc
    isolation: str = ""  # none | namespace | seccomp | sandbox
    trust_summary: str = ""  # one-line trust boundary summary
    evidence: list[str] = field(default_factory=list)


# ------------------------------------------------------------------
# Domain model (top-level container)
# ------------------------------------------------------------------

@dataclass
class BugPattern:
    id: str
    description: str
    what_to_grep: str = ""
    relevant_cwes: list[str] = field(default_factory=list)


@dataclass
class DomainModel:
    version: str = "1"
    target: str = ""
    source_root: str = ""
    concepts: list[Concept] = field(default_factory=list)
    invariants: list[Invariant] = field(default_factory=list)
    contracts: list[Contract] = field(default_factory=list)
    bug_patterns: list[BugPattern] = field(default_factory=list)
    security_context: SecurityContext | None = None
    key_files: list[dict[str, str]] = field(default_factory=list)
    # API vocabulary elicited from study answers, name-verified against
    # the mechanically extracted study items and stamped with a
    # provenance tier (core.concepts.receipts convention). Consumed by
    # DomainVocabulary.from_domain_model (core.audit.condition_smt).
    # Entry shapes:
    #   paired_operations: {acquire, release, kind[, note, provenance]}
    #   nullable_returns:  {name[, when, provenance]} or bare string
    #   auth_predicates:   {name[, kind, provenance]} or bare string
    #   security_fields:   {name[, why, provenance]} or bare string
    #   fallibility_contracts: {name, can_fail[, convention, when,
    #       provenance]} — per-function fallibility (design §2.2.2
    #       structured field; convention: null | negative | errno |
    #       zero_ok | boolean | exception). Consumed by
    #       core.audit.return_contracts as a return-check contract
    #       witness (mechanical tier ⇒ registry-grade).
    #   resource_limits:   {field_or_macro, applies_to[, provenance]}
    #   state_fields:      {field[, struct, authority, monotonic,
    #                        invariant_refs, provenance, receipt]}
    # resource_limits / state_fields are parsed channel-locally
    # (resource_bounds / protocol_state) — deliberately NOT surfaced
    # through DomainVocabulary.
    paired_operations: list[dict[str, Any]] = field(default_factory=list)
    nullable_returns: list[Any] = field(default_factory=list)
    auth_predicates: list[Any] = field(default_factory=list)
    security_fields: list[Any] = field(default_factory=list)
    fallibility_contracts: list[dict[str, Any]] = field(
        default_factory=list,
    )
    resource_limits: list[Any] = field(default_factory=list)
    state_fields: list[Any] = field(default_factory=list)

    # ----- persistence -------------------------------------------

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")
        tmp.rename(path)

    @classmethod
    def load(cls, path: Path) -> DomainModel:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return cls()
        if not isinstance(raw, dict):
            return cls()
        concepts = [
            Concept(**{
                **_filter_fields(Concept, c),
                "evidence": [
                    Evidence(**_filter_fields(Evidence, e))
                    for e in c.get("evidence", [])
                ],
            })
            for c in raw.get("concepts", [])
        ]
        invariants = [
            Invariant(**_filter_fields(Invariant, i))
            for i in raw.get("invariants", [])
        ]
        contracts = [
            Contract(**_filter_fields(Contract, c))
            for c in raw.get("contracts", [])
        ]
        sc_raw = raw.get("security_context")
        security_context = (
            SecurityContext(**_filter_fields(SecurityContext, sc_raw))
            if sc_raw else None
        )
        bug_patterns = [
            BugPattern(**_filter_fields(BugPattern, bp))
            for bp in raw.get("bug_patterns", [])
        ]
        def _vocab_list(key: str) -> list:
            value = raw.get(key, [])
            if not isinstance(value, list):
                return []
            return [v for v in value if isinstance(v, (dict, str))]

        return cls(
            version=raw.get("version", "1"),
            target=raw.get("target", ""),
            source_root=raw.get("source_root", ""),
            concepts=concepts,
            invariants=invariants,
            contracts=contracts,
            bug_patterns=bug_patterns,
            security_context=security_context,
            key_files=raw.get("key_files", []),
            paired_operations=[
                p for p in _vocab_list("paired_operations")
                if isinstance(p, dict)
            ],
            nullable_returns=_vocab_list("nullable_returns"),
            auth_predicates=_vocab_list("auth_predicates"),
            security_fields=_vocab_list("security_fields"),
            fallibility_contracts=[
                p for p in _vocab_list("fallibility_contracts")
                if isinstance(p, dict)
            ],
            resource_limits=[
                r for r in _vocab_list("resource_limits")
                if isinstance(r, dict)
            ],
            state_fields=[
                s for s in _vocab_list("state_fields")
                if isinstance(s, dict)
            ],
        )

    # ----- query helpers -----------------------------------------

    def get_concept(self, concept_id: str) -> Concept | None:
        for c in self.concepts:
            if c.id == concept_id:
                return c
        return None

    def get_contracts_for(self, function: str) -> list[Contract]:
        return [c for c in self.contracts if c.function == function]

    def concepts_at_confidence(self, min_grade: str) -> list[Concept]:
        try:
            floor = CONFIDENCE_GRADES.index(min_grade)
        except ValueError:
            return []
        return [
            c for c in self.concepts
            if c.confidence in CONFIDENCE_GRADES
            and CONFIDENCE_GRADES.index(c.confidence) >= floor
        ]
