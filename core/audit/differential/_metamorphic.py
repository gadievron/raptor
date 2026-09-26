"""Metamorphic relation witness — dual-controlled, run-scoped.

A metamorphic relation asserts that ONE function must handle two
related inputs equivalently (order-insensitivity, canonical-form
equivalence, parse/serialize round-trips expressed as input pairs).
The LLM proposes the relation and its input pairs; execution and the
verdict are mechanical, and the relation is TRUSTED only after three
controls pass — the first two on the real target (the same
dual-control discipline the checker-synthesis promotion gate uses: a
proposed rule earns authority only by demonstrating both its match
and its silence), the third on the target's conforming peers:

- determinism control: the SAME vector executed twice must produce
  equal observations. A flaky or state-carrying function would mint
  "violations" out of noise.
- sensitivity control: a proposer-supplied should-differ pair must
  produce DIFFERENT observations. A constant/stub function, or an
  observation channel too coarse to distinguish inputs, would make
  every equivalence pair vacuously "hold".
- relation-validity control: the deciding pair re-executed over the
  lead's conforming peers must HOLD on every one of them. The first
  two controls verify the observation channel, not the CLAIM — a
  proposed "equivalence" the whole family violates is a false
  relation (the proposer's invariant is wrong for this codebase),
  not a property of the deviant, so it poisons the witness rather
  than promote it. Only a violation the deviant exhibits ALONE,
  against peers that all satisfy the relation, is promote-capable.

The channel controls run against the real target function, so a
trusted relation's violation is anchored to real code, never to
fixtures — and the validity control anchors the RELATION itself to
the family before any promotion.
A confirmed violation is promote-capable under the same execution
namespace as the family-differential verdicts (one oracle);
relation-holds is fail-to-promote ONLY and never demotes anything;
any member error or failed control poisons the witness to
inconclusive. Relations are run-scoped: nothing here persists them —
a relation trusted on one tree would launder authority onto the next
without re-earning its controls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ..dark_verify._prompts import _extract_json
from ._rails import MAX_RELATION_PAIRS
from ._types import (
    OBS_ERROR,
    VERDICT_INCONCLUSIVE,
    DifferentialVector,
    MemberObservation,
)

# Metamorphic verdicts (the promote-capable one is deliberately NOT
# the family-differential confirm string: records must say which
# witness kind earned the verdict, even though both share one
# execution namespace).
VERDICT_RELATION_VIOLATED = "confirmed-relation-violation"
VERDICT_RELATION_HOLDS = "relation-holds"

#: Relation prose is LLM text carried into run records — bounded like
#: vector rationales.
_MAX_RELATION_CHARS = 300


@dataclass
class MetamorphicRelation:
    """One proposed relation: prose, equivalence pairs, and the
    should-differ control pair."""

    relation: str
    pairs: list[tuple[DifferentialVector, DifferentialVector]] = field(
        default_factory=list,
    )
    differ: tuple[DifferentialVector, DifferentialVector] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "relation": self.relation,
            "pairs": [
                {"left": a.to_dict(), "right": b.to_dict()}
                for a, b in self.pairs
            ],
            "differ": (
                {
                    "left": self.differ[0].to_dict(),
                    "right": self.differ[1].to_dict(),
                }
                if self.differ is not None
                else None
            ),
        }


@dataclass
class MetamorphicVerdict:
    """The fold over one relation's controls and pairs."""

    verdict: str
    reason: str
    relation: str
    controls_passed: bool = False
    #: Index of the deciding pair for a violation, -1 otherwise.
    pair_index: int = -1
    #: Whether the relation-validity control passed: the deciding
    #: pair held on every executed conforming peer. False until
    #: :func:`validate_relation_on_family` earns it — a violation
    #: verdict without it is provisional and never promote-capable.
    family_validated: bool = False
    observations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "relation": self.relation,
            "controls_passed": self.controls_passed,
            "pair_index": self.pair_index,
            "family_validated": self.family_validated,
            "observations": list(self.observations),
        }


# -- prompt + parser ----------------------------------------------------------

_RELATION_TEMPLATE = """\
You are testing a single function in a codebase for a metamorphic
invariant.

## Target

The function's file and name are given in the `file` and `function`
slots. The static-analysis lead text arrives as an untrusted block
(kind `lead-description`).

## Task

Propose ONE metamorphic relation the function should satisfy —
an invariant relating two inputs it must handle equivalently
(order-insensitivity, canonical vs non-canonical spellings of the
same value, equivalent unit spellings, round-trip identities
expressed as input pairs). Then supply:

- up to 3 equivalence pairs: two argument vectors the relation says
  the function must handle IDENTICALLY;
- one should-differ pair: two argument vectors the relation does NOT
  relate, which a working implementation must handle DIFFERENTLY
  (this control proves the comparison can distinguish inputs at all).

## Output format

Return a JSON object with these fields:
- "relation": one sentence naming the invariant
- "pairs": list of up to 3 objects, each with "left" and "right",
  where each side is {"args": [...], "kwargs": {...}} (JSON-serialisable
  values only; kwargs for Python targets only, {} otherwise)
- "differ": one object of the same {"left": ..., "right": ...} shape

Return ONLY the JSON object. No markdown fencing, no explanation outside the JSON.
"""


def build_relation_prompt(
    lead: Mapping[str, Any],
    *,
    model_id: str = "",
) -> tuple[str, str]:
    """Build the enveloped ``(user, system)`` pair for one relation
    proposal (same envelope discipline as the vector prompt)."""
    from core.security.prompt_envelope import TaintedString, UntrustedBlock
    from core.security.prompt_framing import with_audit_framing

    from .._util import envelope_prompt

    file = str(lead.get("file") or "")
    function = str(lead.get("function") or "")
    blocks = (
        UntrustedBlock(
            content=str(lead.get("description") or "(no description)"),
            kind="lead-description",
            origin=f"{file}:{function}",
        ),
    )
    slots = {
        "file": TaintedString(value=file, trust="untrusted"),
        "function": TaintedString(value=function, trust="untrusted"),
    }
    return envelope_prompt(
        with_audit_framing(_RELATION_TEMPLATE), blocks, slots,
        model_id=model_id,
    )


def _vector_from(item: Any) -> DifferentialVector | None:
    if not isinstance(item, dict):
        return None
    args = item.get("args", [])
    kwargs = item.get("kwargs", {})
    if not isinstance(args, list) or not isinstance(kwargs, dict):
        return None
    if not all(isinstance(k, str) for k in kwargs):
        return None
    return DifferentialVector(args=list(args), kwargs=dict(kwargs))


def _pair_from(
    item: Any,
) -> tuple[DifferentialVector, DifferentialVector] | None:
    if not isinstance(item, dict):
        return None
    left = _vector_from(item.get("left"))
    right = _vector_from(item.get("right"))
    if left is None or right is None:
        return None
    return left, right


def parse_relation_response(response: str) -> MetamorphicRelation | None:
    """Parse the LLM's relation proposal.

    Fail-closed intake: a missing or malformed should-differ pair
    refuses the whole response (without the sensitivity control the
    relation can never be trusted, so nothing else in it is usable),
    malformed equivalence pairs are dropped, and the survivors are
    capped at the pair rail. Returns ``None`` when nothing executable
    remains.
    """
    data = _extract_json(response)
    if data is None:
        return None

    relation = str(data.get("relation", "")).strip()
    if not relation:
        return None

    differ = _pair_from(data.get("differ"))
    if differ is None:
        return None

    raw = data.get("pairs")
    if not isinstance(raw, list):
        return None
    pairs: list[tuple[DifferentialVector, DifferentialVector]] = []
    for item in raw:
        if len(pairs) >= MAX_RELATION_PAIRS:
            break
        pair = _pair_from(item)
        if pair is not None:
            pairs.append(pair)
    if not pairs:
        return None

    return MetamorphicRelation(
        relation=relation[:_MAX_RELATION_CHARS],
        pairs=pairs,
        differ=differ,
    )


# -- classification -----------------------------------------------------------


def _obs_equal(a: MemberObservation, b: MemberObservation) -> bool:
    """Observation equality for the relation: same protocol kind AND
    same observed value. Only meaningful between valid observations —
    callers must have excluded errors first."""
    return (a.kind, a.value) == (b.kind, b.value)


def classify_relation(
    relation: MetamorphicRelation,
    *,
    determinism: tuple[MemberObservation, MemberObservation],
    sensitivity: tuple[MemberObservation, MemberObservation],
    pairs: list[tuple[MemberObservation, MemberObservation]],
) -> MetamorphicVerdict:
    """The verdict for one relation, fail-closed in this order:

    1. any member error anywhere poisons the witness;
    2. a failed determinism control leaves the relation untrusted
       (equal-vector noise would mint violations);
    3. a failed sensitivity control leaves the relation untrusted
       (an undiscriminating observation channel would make every
       pair vacuously "hold" — and, worse, lend false authority to
       any violation it did happen to show);
    4. only then do the equivalence pairs classify: any unequal pair
       is a confirmed violation — PROVISIONAL until
       :func:`validate_relation_on_family` additionally shows the
       deciding pair holding on the conforming peers
       (``family_validated``); all-equal is
       relation-holds (fail-to-promote only — a relation holding on
       a handful of pairs never demotes anything).
    """
    observations = (
        [o.to_dict() for o in determinism]
        + [o.to_dict() for o in sensitivity]
        + [o.to_dict() for p in pairs for o in p]
    )

    def _v(verdict: str, reason: str, *, controls: bool = False,
           pair_index: int = -1) -> MetamorphicVerdict:
        return MetamorphicVerdict(
            verdict=verdict, reason=reason, relation=relation.relation,
            controls_passed=controls, pair_index=pair_index,
            observations=observations,
        )

    every = list(determinism) + list(sensitivity) + [
        o for p in pairs for o in p
    ]
    broken = [o for o in every if o.kind == OBS_ERROR]
    if broken:
        return _v(
            VERDICT_INCONCLUSIVE,
            f"member execution(s) did not complete validly: "
            f"{broken[0].detail or broken[0].member}",
        )

    if not _obs_equal(*determinism):
        return _v(
            VERDICT_INCONCLUSIVE,
            "determinism control failed (same vector produced "
            "differing observations) — relation untrusted",
        )
    if _obs_equal(*sensitivity):
        return _v(
            VERDICT_INCONCLUSIVE,
            "sensitivity control failed (should-differ pair produced "
            "equal observations) — relation untrusted",
        )

    if not pairs:
        return _v(
            VERDICT_INCONCLUSIVE,
            "no equivalence pair executed",
            controls=True,
        )
    for i, (left, right) in enumerate(pairs):
        if not _obs_equal(left, right):
            return _v(
                VERDICT_RELATION_VIOLATED,
                f"equivalence pair {i} diverged under a "
                f"dual-controlled relation",
                controls=True,
                pair_index=i,
            )
    return _v(
        VERDICT_RELATION_HOLDS,
        f"all {len(pairs)} equivalence pair(s) held",
        controls=True,
    )


def validate_relation_on_family(
    verdict: MetamorphicVerdict,
    peers: list[tuple[MemberObservation, MemberObservation]],
    *,
    quorum: int,
) -> MetamorphicVerdict:
    """The relation-validity control: re-classify a provisional
    violation against the deciding pair's observations on the
    conforming peers.

    The channel controls proved the comparison CAN see differences on
    the target; they never tested whether the proposed equivalence is
    a true invariant of this codebase. This control does: each peer
    executed the deciding pair's left and right vectors, and the
    relation is trusted only if every executed peer HELD it. Fail
    closed, in order:

    1. any peer error poisons the witness (a broken peer is neither a
       hold nor a violation);
    2. any peer VIOLATING the relation poisons the witness — the
       family disagrees with the proposer's invariant, so the
       "violation" characterises a false relation, not the deviant;
    3. fewer executed peers than ``quorum`` poisons the witness (a
       relation vouched for by too few peers earns no authority);
    4. otherwise the violation survives with ``family_validated``
       set — the ONLY path to a promote-capable metamorphic verdict.

    Anything other than a provisional violation passes through
    unchanged: holds and inconclusives have nothing to validate.
    """
    if verdict.verdict != VERDICT_RELATION_VIOLATED:
        return verdict

    observations = verdict.observations + [
        o.to_dict() for p in peers for o in p
    ]

    def _poison(reason: str) -> MetamorphicVerdict:
        return MetamorphicVerdict(
            verdict=VERDICT_INCONCLUSIVE, reason=reason,
            relation=verdict.relation,
            controls_passed=verdict.controls_passed,
            pair_index=verdict.pair_index,
            observations=observations,
        )

    broken = [
        o for p in peers for o in p if o.kind == OBS_ERROR
    ]
    if broken:
        return _poison(
            f"relation-validity control: peer execution(s) did not "
            f"complete validly: {broken[0].detail or broken[0].member}",
        )
    violating = [
        left.member for left, right in peers
        if not _obs_equal(left, right)
    ]
    if violating:
        return _poison(
            f"relation-validity control: conforming peer(s) also "
            f"violate the relation ({', '.join(violating[:3])}) — "
            f"false relation, not a deviant property",
        )
    if len(peers) < quorum:
        return _poison(
            f"relation-validity control: {len(peers)} conforming "
            f"peer(s) executed the deciding pair; need {quorum}",
        )

    return MetamorphicVerdict(
        verdict=verdict.verdict,
        reason=(
            f"{verdict.reason}; relation held on all {len(peers)} "
            f"executed conforming peers"
        ),
        relation=verdict.relation,
        controls_passed=verdict.controls_passed,
        pair_index=verdict.pair_index,
        family_validated=True,
        observations=observations,
    )
