"""Explicit checker outcomes beside the legacy positive-receipt list."""

from dataclasses import asdict, dataclass, field, replace

from .claims import ClaimRevision
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
class ClaimRefutation:
    file: str
    function: str
    line_start: int
    hypothesis: str
    checks: tuple[ProbeOutcome, ...]
    source_identity: SourceIdentity | None = None
    claim_revision: ClaimRevision | None = field(default=None, compare=False)

    def __post_init__(self):
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
        return record


def claims_refuted(outcome, hypotheses: list[str], *, source_identity) -> bool:
    """Every active claim needs its own pipeline-created scoped receipt."""
    receipts = getattr(outcome, "claim_refutations", ()) or ()
    if not isinstance(receipts, (tuple, list)):
        return False
    return bool(hypotheses) and all(any(
        isinstance(receipt, ClaimRefutation) and receipt.matches(
            file=outcome.file, function=outcome.function,
            line_start=outcome.line, hypothesis=hypothesis,
            source_identity=source_identity,
        ) for receipt in receipts
    ) for hypothesis in hypotheses)


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
