"""Claim-bound evidence selection; orchestration owns dispatch and mutation."""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ClaimVerification:
    hypothesis: dict[str, Any]
    receipts: tuple[str, ...] = ()
    refuted: bool = False

    def __post_init__(self):
        object.__setattr__(self, "hypothesis", dict(self.hypothesis))
        object.__setattr__(self, "receipts", tuple(self.receipts))
        if self.refuted and self.receipts:
            raise ValueError("a refuted claim cannot also carry confirming receipts")


@dataclass(frozen=True)
class ClaimSupport:
    verification: ClaimVerification
    receipts: tuple[str, ...]


def supported_claims(
    verifications: Iterable[ClaimVerification], *,
    receipt_can_promote: Callable[[str], bool],
) -> list[ClaimSupport]:
    """Only promotion-grade evidence can support a selected claim.

    Detection leads cannot upgrade each other, even on the same mechanism.
    Keep the exported claim aligned with its actual supporting receipts.
    """
    supported = []
    for verification in verifications:
        receipts = tuple(dict.fromkeys(verification.receipts))
        strong = tuple(r for r in receipts if receipt_can_promote(r))
        if strong:
            supported.append(ClaimSupport(verification, strong))
    return supported
