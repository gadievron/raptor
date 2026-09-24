"""Domain model for semantic concept learning.

Dataclasses for concepts, invariants, contracts, and the composite
domain model.  Serialise to / from ``domain-model.json``.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from core.hash import sha256_string


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


def fold_ws(value: object) -> str:
    """Collapse whitespace runs — including every line-boundary
    character — to a single space, trimmed.

    THE writer-side normalisation for every free-text field value
    rendered into a SAGE concept-row line (evidence fields here;
    descriptions, invariants, contracts in
    ``core.sage.hooks.store_study_concepts``). A raw line boundary
    inside a value would let the remainder of the value stand as a row
    line of its own — e.g. an invariant statement containing
    ``\\nSource hash: x`` mints a line-start mention that shadows the
    genuine field for concepts that store no composite.
    """
    return re.sub(r"\s+", " ", str(value or "")).strip()


def sage_evidence_row(ev: Evidence) -> str:
    """Render one evidence line of a SAGE study-concept row.

    THE writer half of the SAGE evidence grammar. The parsers in
    ``core.concepts.study`` (the shared per-line extraction over
    ``_SAGE_EVIDENCE_RE`` and the staleness verifier / reconstruction
    parser built on it) re-derive ``(type, file, line, hash,
    observation)`` from exactly this shape, so the writer
    (``core.sage.hooks.store_study_concepts``) must render through
    here: a writer/parser drift silently disables the cross-run study
    skip optimisation (the parse fails closed to the seed path).
    Round-trip covered by
    ``core/concepts/tests/test_sage_row_grammar.py``.

    Field values come from an LLM and are not grammar-aware, so they
    are normalised until the rendered text re-parses as ONE evidence
    line whose parsed hash is this evidence's hash (or none — a value
    the grammar cannot carry, e.g. a file path containing the spaced
    dash separator, degrades to a hashless parse rather than a
    divergent one):

    - the type collapses to the grammar's ``\\w+`` token (a free-typed
      ``code-path`` otherwise shifts the whole parse);
    - newlines and other whitespace runs in file/observation fold to a
      single space (a raw line boundary splits the line, and the
      remainder of the value then reads as further row lines);
    - a hex hash is lowercased to the tag alphabet; a hash containing
      whitespace is dropped entirely (rendered verbatim it would
      smuggle a line boundary into the row), and any other non-hex
      value renders as given and simply never parses as a hash tag;
    - an empty observation becomes ``(none)`` — a line ending at its
      dash does not re-parse, silently dropping its hash from the
      verifiable set.
    """
    kind = re.sub(r"\W", "_", str(ev.type or "")) or "unknown"
    file = fold_ws(ev.file)
    obs = fold_ws(ev.observation) or "(none)"
    raw_hash = str(ev.hash or "")
    if not re.fullmatch(r"\S+", raw_hash):
        # A hash containing whitespace (or empty) can never parse as a
        # tag, and folding it would render junk; rendering it verbatim
        # would smuggle a line boundary into the row. Dropped — the
        # evidence line stays, hashless.
        raw_hash = ""
    elif re.fullmatch(r"[0-9a-fA-F]+", raw_hash):
        raw_hash = raw_hash.lower()
    # `is not None`, not truthiness: line 0 is a real anchor for
    # whole-file evidence, and dropping it desyncs the writer/parser
    # round trip (the hash tag would re-parse with no line).
    loc = f"{file}:{ev.line}" if ev.line is not None else file
    h_tag = f" [h={raw_hash}]" if raw_hash else ""
    return f"  Evidence ({kind}): {loc}{h_tag} — {obs}"


def evidence_hash_composite(hashes: Iterable[str]) -> str:
    """Fold per-evidence hashes into a row's composite source hash.

    THE single formula behind the ``Source hash:`` value of a SAGE
    study-concept row: order-independent (sorted), duplicate-preserving
    (one entry per evidence line, so two evidence lines sharing a hash
    fold differently from one), full SHA-256 hex. No hashes → ``""``
    (a concept whose evidence carries no parseable hashes stores an
    empty composite).

    Two callers, one formula: the writer
    (``core.sage.hooks.store_study_concepts``) folds the hashes parsed
    back out of the row content it is about to store and binds the
    result into the row MAC; the recall-side verifier
    (``core.concepts.study.stamped_evidence_composite``) re-folds the
    same extraction and requires equality with the MAC-bound value. A
    formula drift between the two would silently demote every stored
    concept row from the mechanical skip/seed path, so both sides must
    compute through here.

    Rows minted before this formula existed carry a 12-hex-char prefix
    of the same fold; the recall gate prefix-compares for exactly that
    src length so they keep verifying (the length is trustworthy there
    because src is MAC-bound).
    """
    hash_list = sorted(hashes)
    if not hash_list:
        return ""
    return sha256_string("|".join(hash_list))


# ------------------------------------------------------------------
# Concept
# ------------------------------------------------------------------

CONFIDENCE_GRADES = ("inferred", "observed", "traced", "corroborated", "documented", "tested")

#: Decompiled-evidence grading ceiling — the ONE spelling shared by
#: every consumer that grades decomp-derived evidence (binary --study's
#: domain-model clamp, the audit's tree-wide decomp sweep records).
#: Decompilation is derived evidence about a binary, not ground truth:
#: nothing whose evidence is decompilation-only may grade above this
#: ceiling, and it always carries :data:`DECOMP_EVIDENCE_TAG` so
#: downstream weight policies can see the provenance.
DECOMP_EVIDENCE_MAX_CONFIDENCE = "traced"
DECOMP_EVIDENCE_TAG = "decompiled-evidence"


def clamp_decomp_confidence(confidence: object) -> str:
    """Clamp *confidence* to the decompiled-evidence ceiling.

    Grades above :data:`DECOMP_EVIDENCE_MAX_CONFIDENCE` come back as
    the ceiling; legal below-ceiling grades pass through unchanged so
    an honestly lower grade ("observed") is never inflated. Unknown
    grades floor to ``"inferred"`` — the unknown-grade fallback must
    never LIFT a grade.
    """
    c = str(confidence or "inferred")
    try:
        if (CONFIDENCE_GRADES.index(c)
                > CONFIDENCE_GRADES.index(DECOMP_EVIDENCE_MAX_CONFIDENCE)):
            return DECOMP_EVIDENCE_MAX_CONFIDENCE
    except ValueError:
        return "inferred"
    return c


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
    # Audit strategies this concept informs (values from
    # core.audit.strategy.ALL_STRATEGIES). Stamped mechanically at
    # domain-model save time; consumed by the context-staleness gate
    # in gap computation (a new concept only re-queues functions
    # whose current strategies intersect it — AR-7). Empty = unstamped
    # legacy concept, treated as relevant to nothing (storm-safe).
    related_strategies: list[str] = field(default_factory=list)


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
    # Optional per the teach JSON schema (teach.md TEACH-4); the SAGE
    # store surfaces the first few as row tags.
    mechanism_tags: list[str] = field(default_factory=list)
    provenance: str = ""
    receipt: dict[str, Any] | None = None
    # Staleness marker: "" (fresh/unchecked) or "stale" — set by the
    # prior-model quarantine when the verbatim receipt no longer
    # verifies against the current source. Tier-gated consumers
    # (audit_bridge._tier_tag) render stale entries as
    # [stale-unverified] hints, never as receipt-backed facts.
    state: str = ""


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
    # Span the hash was computed over (``_stamp_contract_hashes``):
    # {"file": <study-item file>, "start": N, "end": M}. Recorded so
    # the staleness check can re-hash the same span later; ``hash``
    # alone is unverifiable without it. None on pre-span legacy
    # models — those contracts are skipped by the staleness check
    # (no baseline), same as unhashed concept evidence.
    hash_span: dict[str, Any] | None = None
    provenance: str = ""
    receipt: dict[str, Any] | None = None
    # Staleness marker: "" (fresh/unchecked) or "stale" — set when the
    # stamped span hash no longer matches the source. Stale contracts
    # are dropped from the authority-toned review primers and render
    # as [stale-unverified] in context blocks.
    state: str = ""


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
        # Shared atomic writer: unique tempfile in the destination
        # directory + fsync + os.replace. A fixed '<path>.tmp' name
        # let two concurrent studies interleave their temp writes and
        # rename a torn model into place.
        from core.atomic_fs import write_text_atomically

        write_text_atomically(
            path, json.dumps(asdict(self), indent=2) + "\n",
        )

    @classmethod
    def load(cls, path: Path) -> DomainModel:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return cls()
        if not isinstance(raw, dict):
            return cls()
        # Tolerate schema drift in on-disk models: any record written by
        # an older schema (or a partial writer) must degrade, never
        # crash the loader — sibling-run models are consulted
        # opportunistically and may predate required fields. The
        # defaults cover EVERY dataclass the loader constructs, not
        # just Concept: the Concept.description drift recurred as
        # Invariant.concept when a later schema added that field.
        def _drift_load(dc_type: type, record: dict) -> dict:
            defaults = {
                f.name: "" for f in dataclasses.fields(dc_type)
                if f.default is dataclasses.MISSING
                and f.default_factory is dataclasses.MISSING
                and f.type in ("str", str)
            }
            return {**defaults, **_filter_fields(dc_type, record)}

        def _dict_records(container: Any) -> list[dict]:
            """Dict-shaped records of a list-shaped container.

            Non-dict records (a bare-string evidence entry — a shape
            the study pipeline itself accepts from the LLM) and
            non-list containers (a dict where a list was expected)
            must degrade to skipped records / an empty list, never
            crash the loader: sibling-run and canonical models are
            consulted opportunistically and may carry any older
            writer's shape.
            """
            if not isinstance(container, list):
                return []
            return [r for r in container if isinstance(r, dict)]

        concepts = [
            Concept(**{
                **_drift_load(Concept, c),
                "evidence": [
                    Evidence(**_drift_load(Evidence, e))
                    for e in _dict_records(c.get("evidence", []))
                ],
            })
            for c in _dict_records(raw.get("concepts", []))
        ]
        invariants = [
            Invariant(**_drift_load(Invariant, i))
            for i in _dict_records(raw.get("invariants", []))
        ]
        contracts = [
            Contract(**_drift_load(Contract, c))
            for c in _dict_records(raw.get("contracts", []))
        ]
        sc_raw = raw.get("security_context")
        security_context = (
            SecurityContext(**_drift_load(SecurityContext, sc_raw))
            if isinstance(sc_raw, dict) else None
        )
        bug_patterns = [
            BugPattern(**_drift_load(BugPattern, bp))
            for bp in _dict_records(raw.get("bug_patterns", []))
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

    def get_contracts_for(
        self, function: str, file: str | None = None,
    ) -> list[Contract]:
        """Contracts for *function*, optionally narrowed to *file*.

        Contracts are keyed by (function, file) — same-named functions
        in different files carry different contracts, so a name-only
        lookup returns every file's contract for that name. Callers
        that know the file should pass it; contracts recording no file
        always pass the narrowing.
        """
        return [
            c for c in self.contracts
            if c.function == function
            and (file is None or not c.file or c.file == file)
        ]

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
