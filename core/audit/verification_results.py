"""Explicit checker outcomes beside the legacy positive-receipt list."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ProbeOutcome:
    tool: str
    verdict: str
    rule_id: str
    reason: str = ""


@dataclass(frozen=True)
class ClaimRefutation:
    file: str
    function: str
    line_start: int
    hypothesis: str
    checks: tuple[ProbeOutcome, ...]

    def __post_init__(self):
        object.__setattr__(self, "checks", tuple(self.checks))

    def matches(self, *, file, function, line_start, hypothesis) -> bool:
        return (self.file, self.function, self.line_start, self.hypothesis) == (
            file, function, line_start or 0, hypothesis,
        ) and bool(self.checks) and all(
            isinstance(check, ProbeOutcome) and check.verdict == "refuted" and check.rule_id
            for check in self.checks
        )

    def to_record(self, *, action="claim_refutation") -> dict:
        return {"action": action, "file": self.file, "function": self.function,
                "line_start": self.line_start, "hypothesis": self.hypothesis,
                "checks": [asdict(check) for check in self.checks]}


def claims_refuted(outcome, hypotheses: list[str]) -> bool:
    """Every active claim needs its own pipeline-created scoped receipt."""
    receipts = getattr(outcome, "claim_refutations", ()) or ()
    if not isinstance(receipts, (tuple, list)):
        return False
    return bool(hypotheses) and all(any(
        isinstance(receipt, ClaimRefutation) and receipt.matches(
            file=outcome.file, function=outcome.function,
            line_start=outcome.line, hypothesis=hypothesis,
        ) for receipt in receipts
    ) for hypothesis in hypotheses)


class ToolChainResult(list[str]):
    """List-compatible confirmations with scoped checker outcomes.

    An empty legacy list contains no negative evidence. Only an
    explicit ``refuted`` outcome on this exact claim can supply it.
    """

    def __init__(self, receipts=(), *, file="", function="", line_start=0, hypothesis=""):
        super().__init__(receipts)
        self.scope = (file, function, line_start or 0, hypothesis)
        self.outcomes: list[ProbeOutcome] = []

    def observe(self, tool: str, verdict: str, rule_id: str, reason: str = "") -> None:
        self.outcomes.append(ProbeOutcome(tool, verdict, rule_id, reason))

    def refutations(self, *, file, function, line_start, hypothesis) -> tuple[ProbeOutcome, ...]:
        if self.scope != (file, function, line_start or 0, hypothesis):
            return ()
        if self or any(outcome.verdict == "confirmed" for outcome in self.outcomes):
            return ()  # conflicting observations need adjudication
        return tuple(outcome for outcome in self.outcomes
                     if outcome.verdict == "refuted" and outcome.rule_id)

    def refutation_record(self, *, file, function, line_start, hypothesis) -> dict | None:
        receipt = self.refutation(file=file, function=function, line_start=line_start, hypothesis=hypothesis)
        return receipt.to_record(action="ihv_refutation") if receipt else None

    def refutation(self, *, file, function, line_start, hypothesis) -> ClaimRefutation | None:
        outcomes = self.refutations(file=file, function=function, line_start=line_start, hypothesis=hypothesis)
        if not outcomes:
            return None
        return ClaimRefutation(file, function, line_start or 0, hypothesis, outcomes)
