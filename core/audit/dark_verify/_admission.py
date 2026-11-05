"""Keep observed behavior separate from independently detected violations."""

from ._types import DarkVerifyResult

SANITIZER_RECEIPT = "dark_verify:sanitizer-violation"


def witness_can_confirm(result, *, finding_key: str) -> bool:
    """A matched prediction alone does not establish a defect.

    The native classifier sets violation_observed only for a matched,
    instrumented sanitizer report within the authenticated call window.
    """
    return (isinstance(result, DarkVerifyResult)
            and result.finding_key == finding_key
            and result.verdict == "confirmed"
            and result.violation_observed is True
            and result.oracle_reliability == "decisive")
