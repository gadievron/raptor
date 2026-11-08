"""Claim-bound evidence selection; orchestration owns dispatch and mutation."""

from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from .refutation_source import SourceIdentity
from .verification_results import VerificationScope


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
    binding: VerificationScope | None = None

    def __init__(self, hypothesis: dict[str, Any], receipts: tuple[str, ...] = (), refuted: bool = False,
                 *, binding: VerificationScope | None = None):
        if binding is not None and not isinstance(binding, VerificationScope):
            raise TypeError("verification binding must be a VerificationScope or None")
        object.__setattr__(self, "_hypothesis", deepcopy(dict(hypothesis)))
        object.__setattr__(self, "receipts", tuple(receipts))
        object.__setattr__(self, "refuted", refuted)
        object.__setattr__(self, "binding", binding)
        if self.refuted and self.receipts:
            raise ValueError("a refuted claim cannot also carry confirming receipts")

    @property
    def hypothesis(self) -> dict[str, Any]:
        return deepcopy(self._hypothesis)

    def scope_rejection(self, *, file, function, line_start, hypothesis, source_identity: SourceIdentity | None) -> str | None:
        """Return a known binding contradiction, never a proof certificate.

        Legacy unbound receipts gain no scope or freshness guarantee. They
        retain their existing grading policy until their producers migrate.
        """
        if hypothesis != self._hypothesis.get("mechanism"):
            return "claim-revised"
        if self.binding is None:
            return None
        if not self.binding.has_claim:
            return "unbound-claim"
        if not self.binding.matches_claim(file=file, function=function, line_start=line_start, hypothesis=hypothesis):
            return "claim-scope-mismatch"
        if self.binding.source_identity is not None:
            if not isinstance(self.binding.source_identity, SourceIdentity):
                return "unrecognized-source-identity"
            if self.binding.source_identity != source_identity:
                return "source-version-drift"
        return None


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
