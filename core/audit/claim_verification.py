"""Claim-bound evidence selection; orchestration owns dispatch and mutation."""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from .evidence_grade import is_tool_evidence


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
    channels: tuple[str, ...] = ()
    posterior_mean: float = 0.0


def supported_claims(
    verifications: Iterable[ClaimVerification], *,
    receipt_can_promote: Callable[[str], bool],
    aggregate: Callable[[list[str]], tuple[list[str], float]],
) -> list[ClaimSupport]:
    """Apply existing evidence policy separately to each claim.

    Two weak signals for different claims cannot corroborate each other.
    A strong receipt is selected ahead of a detection lead on that claim,
    keeping the exported mechanism and evidence aligned.
    """
    supported = []
    for verification in verifications:
        receipts = tuple(dict.fromkeys(verification.receipts))
        strong = tuple(r for r in receipts if receipt_can_promote(r))
        if strong:
            supported.append(ClaimSupport(verification, strong))
        elif receipts and is_tool_evidence("+".join(receipts)):
            channels, mean = aggregate(list(receipts))
            if channels:
                supported.append(ClaimSupport(verification, receipts, tuple(channels), mean))
    return supported
