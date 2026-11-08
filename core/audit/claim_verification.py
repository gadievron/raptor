"""Claim-bound evidence selection; orchestration owns dispatch and mutation."""

from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


def unverified_critique(record: dict[str, Any]) -> dict[str, Any]:
    """Retain a model's objection without granting refutation authority.

    A named guard or proposed check is still a model judgment. Scoped
    checker refutations are admitted separately through ClaimRefutation;
    neither a callback flag nor model agreement can substitute for them.
    """
    return {
        **record,
        "proposed_refutation": (
            record.get("verdict") == "refuted" or record.get("refuted") is True
            or record.get("proposed_refutation") is True
        ),
        "refuted": False,
        "adjudication": "unverified",
    }


@dataclass(frozen=True, init=False)
class ClaimVerification:
    """A fixed claim snapshot paired with the receipts that tested it.

    Readers receive ordinary dictionaries so existing context gates retain
    their input contract. Mutating those dictionaries, or the original
    producer's nested data, cannot revise a claim under existing receipts.
    A changed claim requires a new verification record.
    """

    _hypothesis: dict[str, Any] = field(repr=False)
    receipts: tuple[str, ...] = ()
    refuted: bool = False

    def __init__(self, hypothesis: dict[str, Any], receipts: tuple[str, ...] = (), refuted: bool = False):
        object.__setattr__(self, "_hypothesis", deepcopy(dict(hypothesis)))
        object.__setattr__(self, "receipts", tuple(receipts))
        object.__setattr__(self, "refuted", refuted)
        if self.refuted and self.receipts:
            raise ValueError("a refuted claim cannot also carry confirming receipts")

    @property
    def hypothesis(self) -> dict[str, Any]:
        return deepcopy(self._hypothesis)


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
