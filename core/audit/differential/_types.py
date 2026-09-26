"""Data model for differential family execution.

A consistency lead says "n peers do X, this one differs" from static
text. The differential oracle asks the peers themselves: run the
deviant AND its conforming family members on one shared argument
vector, in separate sandboxed processes, and compare what the harness
protocol reports. The comparison never trusts member output as
anything but data — verdicts come from the comparison contract over
authenticated protocol observations.

Verdict vocabulary (per vector and per lead):

- ``confirmed-directional-divergence`` — the deviant ACCEPTED an
  input every executed conforming peer REJECTED. The one
  promote-capable verdict: divergence in the security-relevant
  direction, witnessed by execution.
- ``divergence-nondirectional`` — the family diverged, but not in a
  direction the contract can call (value differences, mixed peers,
  deviant stricter than its peers). Lead corroboration only.
- ``family-agrees`` — every executed member behaved identically.
  Fails to promote and NOTHING more: agreement on a handful of
  vectors never demotes a finding (absence of divergence on three
  inputs is not absence of the bug).
- ``inconclusive`` — some member did not execute validly, or the
  conforming quorum was not met. Fail-closed: no verdict extends to
  members that did not execute.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Comparison contracts the proposer may choose from.
CONTRACT_RETURN_EQUIVALENCE = "return-equivalence"
CONTRACT_ACCEPT_REJECT = "accept-reject-equivalence"
CONTRACT_EXCEPTION_PARITY = "exception-parity"

COMPARISON_CONTRACTS = frozenset({
    CONTRACT_RETURN_EQUIVALENCE,
    CONTRACT_ACCEPT_REJECT,
    CONTRACT_EXCEPTION_PARITY,
})

# Verdicts.
VERDICT_CONFIRMED = "confirmed-directional-divergence"
VERDICT_NONDIRECTIONAL = "divergence-nondirectional"
VERDICT_FAMILY_AGREES = "family-agrees"
VERDICT_INCONCLUSIVE = "inconclusive"

# Member observation kinds (derived ONLY from the authenticated
# harness protocol status — see _classify.observation_from_result).
OBS_ACCEPT = "accept"
OBS_REJECT = "reject"
OBS_ERROR = "error"


@dataclass
class DifferentialVector:
    """One shared argument vector, executed identically by every
    member."""

    args: list[Any] = field(default_factory=list)
    kwargs: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "args": self.args,
            "kwargs": self.kwargs,
            "rationale": self.rationale,
        }


@dataclass
class MemberObservation:
    """What one member's harness reported for one vector."""

    member: str   # function name
    file: str
    kind: str     # OBS_ACCEPT | OBS_REJECT | OBS_ERROR
    value: str = ""    # return repr (accept) / exception text (reject)
    detail: str = ""   # classifier detail / error reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "member": self.member,
            "file": self.file,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
        }


@dataclass
class VectorVerdict:
    """The comparison outcome for one shared vector."""

    vector_index: int
    verdict: str
    reason: str
    contract: str
    deviant: MemberObservation | None = None
    conforming: list[MemberObservation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vector_index": self.vector_index,
            "verdict": self.verdict,
            "reason": self.reason,
            "contract": self.contract,
            "deviant": self.deviant.to_dict() if self.deviant else None,
            "conforming": [o.to_dict() for o in self.conforming],
        }


@dataclass
class LeadVerdict:
    """The lead-level fold over a family's vector verdicts."""

    verdict: str
    reason: str
    contract: str
    vectors: list[VectorVerdict] = field(default_factory=list)
    #: Members selected out BEFORE execution (family shrink), each
    #: with its reason. A verdict never extends to these.
    excluded: list[dict[str, str]] = field(default_factory=list)
    #: Conforming members that executed validly on the deciding
    #: vector, and the census family floor they are held to when the
    #: verdict is promote-capable.
    executed_conforming: int = 0
    family_floor: int = 0
    meets_family_floor: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "contract": self.contract,
            "vectors": [v.to_dict() for v in self.vectors],
            "excluded": list(self.excluded),
            "executed_conforming": self.executed_conforming,
            "family_floor": self.family_floor,
            "meets_family_floor": self.meets_family_floor,
        }
