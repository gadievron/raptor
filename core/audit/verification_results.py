"""Explicit checker outcomes beside the legacy positive-receipt list."""

from dataclasses import asdict, dataclass, field, replace

from .claims import ClaimRevision, MaterialAdmission, hypothesis_material_key, validate_material_admission
from .claim_counters import matching_claims
from .refutation_source import SourceIdentity
from .smt_evidence import is_non_refuting_smt_rule

SOURCE_CHANGED_REASON = "source changed or became unavailable after the captured verification snapshot"
SOURCE_VALIDATION_TOOL = "source_binding"
SOURCE_INPUT_RULE = "source-input-unbound"
SOURCE_INPUT_REASON = "reviewed input could not be bound to the identifiable target source file"


@dataclass(frozen=True)
class ProbeOutcome:
    tool: str
    verdict: str
    rule_id: str
    reason: str = ""


@dataclass(frozen=True)
class VerificationScope:
    """The exact claim occurrence and source snapshot submitted to a check.

    Missing source identity remains unknown. This record binds evidence;
    it does not certify the checker model or its conclusion.
    """

    file: str
    function: str
    line_start: int
    hypothesis: str
    source_identity: SourceIdentity | None = None

    @property
    def scope(self) -> tuple[str, str, int, str]:
        return self.file, self.function, self.line_start, self.hypothesis

    @property
    def has_claim(self) -> bool:
        return bool(self.file and self.function and self.hypothesis)

    def matches_claim(self, *, file, function, line_start, hypothesis) -> bool:
        return self.scope == (file, function, line_start or 0, hypothesis)


@dataclass(frozen=True)
class ReviewPublicationScope:
    """Source-unit publication binding; neither claim evidence nor safety proof.

    The caller owns capture before review. A stable source stamp does not
    establish complete source reading, an immutable build or binary identity.
    """

    file: str
    function: str
    line_start: int
    line_end: int
    source_identity: SourceIdentity

    def __post_init__(self):
        if not isinstance(self.source_identity, SourceIdentity):
            raise TypeError("publication requires a known SourceIdentity")
        if (not isinstance(self.file, str) or not self.file or not isinstance(self.function, str) or not self.function
                or type(self.line_start) is not int or self.line_start < 1
                or type(self.line_end) is not int or self.line_end < self.line_start):
            raise ValueError("publication requires an exact source occurrence")

    def matches(self, *, file, function, line_start, line_end, source_identity) -> bool:
        return type(line_start) is int and type(line_end) is int and self.source_identity == source_identity and (
            self.file, self.function, self.line_start, self.line_end) == (
            file, function, line_start, line_end)


@dataclass(frozen=True)
class ClaimRefutation:
    file: str
    function: str
    line_start: int
    hypothesis: str
    checks: tuple[ProbeOutcome, ...]
    source_identity: SourceIdentity | None = None
    claim_revision: ClaimRevision | None = field(default=None, compare=False)
    material_admission: MaterialAdmission | None = None

    def __post_init__(self):
        validate_material_admission(self.material_admission)
        object.__setattr__(self, "checks", tuple(self.checks))
        if self.claim_revision is not None:
            if not isinstance(self.claim_revision, ClaimRevision):
                raise TypeError("claim lineage must be a ClaimRevision or None")
            if not self.claim_revision.matches_occurrence(file=self.file, function=self.function,
                                                          line_start=self.line_start, hypothesis=self.hypothesis):
                raise ValueError("refutation lineage does not match its producer scope")

    def matches(self, *, file, function, line_start, hypothesis, source_identity) -> bool:
        return isinstance(self.source_identity, SourceIdentity) and self.source_identity == source_identity and (
            self.file, self.function, self.line_start, self.hypothesis) == (
            file, function, line_start or 0, hypothesis,
        ) and bool(self.checks) and all(
            isinstance(check, ProbeOutcome) and check.verdict == "refuted" and check.rule_id
            and not (check.tool == "smt" and is_non_refuting_smt_rule(check.rule_id))
            for check in self.checks
        )

    def to_record(self, *, action="claim_refutation") -> dict:
        record = {"action": action, "file": self.file, "function": self.function,
                  "line_start": self.line_start, "hypothesis": self.hypothesis,
                  "source_identity": asdict(self.source_identity) if self.source_identity else None,
                  "checks": [asdict(check) for check in self.checks]}
        if self.claim_revision is not None:
            record["claim_reference"] = self.claim_revision.event_reference()
        if self.material_admission is not None:
            record["material_admission"] = {
                "default_cwe": self.material_admission[0], "declared_material": list(self.material_admission[1]),
                "role": "rejection_context_not_checker_scope",
            }
        return record


def _unambiguous_refutation_material(outcome, hypotheses: list[str], claim_outcome=None) -> bool:
    """A text-scoped receipt cannot distinguish conflicting structured premises.

    Inspect original declarations, before intake can deduplicate by mechanism.
    Compare current and prior declarations together when transferring negative
    evidence. This only narrows authority; lineage IDs do not expand scope.
    """
    requested = {h.strip().casefold() for h in hypotheses if isinstance(h, str)}
    material: dict[str, tuple[str, ...]] = {}
    for declarations in (outcome, claim_outcome):
        if declarations is None:
            continue
        review = getattr(declarations, "review_result", None) or {}
        if not isinstance(review, dict):
            return False
        default_cwe = review.get("cwe_class") or review.get("cwe") or ""
        for rows in (getattr(declarations, "hypotheses", None), review.get("hypotheses")):
            if rows is None:
                continue
            if not isinstance(rows, (list, tuple)):
                return False
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("mechanism"), str):
                    return False
                mechanism = row["mechanism"].strip().casefold()
                if mechanism not in requested:
                    continue
                key = hypothesis_material_key(row, default_cwe=default_cwe)
                if key is None or (mechanism in material and material[mechanism] != key):
                    return False
                material[mechanism] = key
    return True


def _refutation_material_matches(receipt: ClaimRefutation, declarations) -> bool:
    """Keep a known declaration loss from becoming legacy receipt reuse."""
    if receipt.material_admission is None:
        return True
    review = getattr(declarations, "review_result", None) or {}
    if not isinstance(review, dict):
        return False
    entries = matching_claims(receipt.hypothesis, (
        getattr(declarations, "hypotheses", None), review.get("hypotheses"),
    ))
    _, expected = receipt.material_admission
    if not entries:
        return expected == ()
    default_cwe = review.get("cwe_class") or review.get("cwe") or ""
    keys = {hypothesis_material_key(entry, default_cwe=default_cwe) for entry in entries}
    return None not in keys and keys == {expected}


def claims_refuted(outcome, hypotheses: list[str], *, source_identity, claim_outcome=None) -> bool:
    """Every active claim needs an unambiguous pipeline-created scoped receipt.

    claim_outcome supplies prior declarations when receipts are carried by a
    newer assessment. It supplies no evidence or source authority itself.
    Known nonempty declarations require correspondence; an empty-context
    or untracked duplicate cannot erase that requirement. Without explicit
    active-revision linkage, receipt arrival order cannot choose scope.
    Old scoped receipts remain recorded.
    """
    if not _unambiguous_refutation_material(outcome, hypotheses, claim_outcome):
        return False
    receipts = getattr(outcome, "claim_refutations", ()) or ()
    if not isinstance(receipts, (tuple, list)):
        return False
    declarations = claim_outcome if claim_outcome is not None else outcome
    for hypothesis in hypotheses:
        matching = [receipt for receipt in receipts if isinstance(receipt, ClaimRefutation) and receipt.matches(
            file=outcome.file, function=outcome.function, line_start=outcome.line,
            hypothesis=hypothesis, source_identity=source_identity,
        )]
        contextual = [receipt for receipt in matching if receipt.material_admission is not None]
        declared = [receipt for receipt in contextual if receipt.material_admission is not None and receipt.material_admission[1]]
        if not any(_refutation_material_matches(receipt, declarations) for receipt in (declared or contextual or matching)):
            return False
    return bool(hypotheses)


class ToolChainResult(list[str]):
    """List-compatible confirmations with scoped checker outcomes.

    An empty legacy list contains no negative evidence. Only an
    explicit ``refuted`` outcome on this exact claim can supply it.
    """

    def __init__(self, receipts=(), *, file="", function="", line_start=0, hypothesis="", source_identity=None,
                 claim_revision: ClaimRevision | None = None):
        super().__init__(receipts)
        self._binding = VerificationScope(file, function, line_start or 0, hypothesis, source_identity)
        if claim_revision is not None:
            if not isinstance(claim_revision, ClaimRevision):
                raise TypeError("claim lineage must be a ClaimRevision or None")
            if not claim_revision.matches_occurrence(file=file, function=function,
                                                      line_start=line_start, hypothesis=hypothesis):
                raise ValueError("checker lineage does not match its producer scope")
        self._claim_revision = claim_revision
        self.outcomes: list[ProbeOutcome] = []

    @property
    def claim_revision(self) -> ClaimRevision | None:
        return self._claim_revision

    @property
    def binding(self) -> VerificationScope:
        return self._binding

    @property
    def scope(self) -> tuple[str, str, int, str]:
        return self._binding.scope

    @property
    def source_identity(self) -> SourceIdentity | None:
        return self._binding.source_identity

    def observe(self, tool: str, verdict: str, rule_id: str, reason: str = "") -> None:
        self.outcomes.append(ProbeOutcome(tool, verdict, rule_id, reason))

    def invalidate_for_source(self, source_identity: SourceIdentity | None) -> bool:
        """Withdraw probative results when a known dispatch snapshot changed.

        Unknown dispatch identities retain their legacy behavior; False is
        not a freshness certificate. The caller owns the bounded file read
        and records the prior results before publishing this invalidation.
        """
        if self.source_identity is None or self.source_identity == source_identity:
            return False
        changed = bool(self) or any(outcome.verdict in {"confirmed", "refuted"} for outcome in self.outcomes)
        self.clear()
        self.outcomes = [
            replace(outcome, verdict="inconclusive", reason=f"{SOURCE_CHANGED_REASON}; prior {outcome.verdict}: {outcome.reason}")
            if outcome.verdict in {"confirmed", "refuted"} else outcome
            for outcome in self.outcomes
        ]
        return changed

    def refutations(self, *, file, function, line_start, hypothesis) -> tuple[ProbeOutcome, ...]:
        if self.scope != (file, function, line_start or 0, hypothesis):
            return ()
        if self or any(outcome.verdict == "confirmed" for outcome in self.outcomes):
            return ()  # conflicting observations need adjudication
        return tuple(outcome for outcome in self.outcomes
                     if outcome.verdict == "refuted" and outcome.rule_id
                     and not (outcome.tool == "smt" and is_non_refuting_smt_rule(outcome.rule_id)))

    def refutation_record(self, *, file, function, line_start, hypothesis) -> dict | None:
        receipt = self.refutation(file=file, function=function, line_start=line_start, hypothesis=hypothesis)
        return receipt.to_record(action="ihv_refutation") if receipt else None

    def refutation(self, *, file, function, line_start, hypothesis) -> ClaimRefutation | None:
        outcomes = self.refutations(file=file, function=function, line_start=line_start, hypothesis=hypothesis)
        if not outcomes:
            return None
        return ClaimRefutation(file, function, line_start or 0, hypothesis, outcomes, self.source_identity, self.claim_revision)
