"""Explicit checker outcomes beside the legacy positive-receipt list."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ProbeOutcome:
    tool: str
    verdict: str
    rule_id: str
    reason: str = ""


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
        outcomes = self.refutations(file=file, function=function, line_start=line_start, hypothesis=hypothesis)
        if not outcomes:
            return None
        return {
            "action": "ihv_refutation", "file": file, "function": function,
            "line_start": line_start or 0, "hypothesis": hypothesis,
            "checks": [asdict(outcome) for outcome in outcomes],
        }
