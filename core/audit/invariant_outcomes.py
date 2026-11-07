"""Shared aggregation for mathematical invariant preservation receipts."""


def aggregate_verdicts(verdicts):
    """Only unconditional site proofs establish aggregate preservation.

    ``preserved_nonneg`` carries a real negative-input counterexample.
    Its additional domain assumptions are diagnostic, not established facts.
    Empty inputs retain vacuous preservation; census consumers must separately
    account for missing, truncated or budget-skipped sites.
    """
    verdicts = set(verdicts)
    if "violable" in verdicts:
        return "violable"
    if verdicts <= {"preserved"}:
        return "preserved"
    return "inconclusive"
