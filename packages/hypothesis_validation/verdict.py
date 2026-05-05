"""Verdict combinators — the agreement lattice.

The three architectural invariants from PR #309 — "confirmed without
matches → refuted", "refuted with matches → inconclusive", "tool failure
→ inconclusive" — are recovered here as one combinator (`verdict_from`)
plus the lattice meet (`meet`). `aggregate` reduces a list of evidence
into a single verdict by meet, so multi-adapter combination is one
function rather than three hand-coded checks.

Lattice ordering (with INCONCLUSIVE as bottom):

    CONFIRMED   REFUTED
         \\   /
       INCONCLUSIVE

`meet` is commutative and idempotent; equal verdicts compose, any
disagreement collapses to INCONCLUSIVE. This is the property the lattice
property tests pin down.
"""

from __future__ import annotations

from functools import reduce
from typing import Any, Iterable, Union

from .types import Verdict


VerdictLike = Union[Verdict, str]


def _coerce(v: VerdictLike) -> Verdict:
    """Accept either the Enum or the bare string for backward compat.

    The legacy `Literal["confirmed","refuted","inconclusive"]` callers
    pass strings; the typed-layer callers pass `Verdict` members. Both
    must work without forcing a migration.
    """
    if isinstance(v, Verdict):
        return v
    if isinstance(v, str):
        try:
            return Verdict(v)
        except ValueError:
            return Verdict.INCONCLUSIVE
    return Verdict.INCONCLUSIVE


def meet(a: VerdictLike, b: VerdictLike) -> Verdict:
    """Agreement lattice meet: equal verdicts compose; disagreement is bottom.

    Properties (verified by `tests/test_typed_layer.py`):
      - idempotence:    meet(x, x) == x
      - commutativity:  meet(a, b) == meet(b, a)
      - bottom:         meet(INCONCLUSIVE, x) == INCONCLUSIVE
    """
    av, bv = _coerce(a), _coerce(b)
    return av if av == bv else Verdict.INCONCLUSIVE


def verdict_from(
    evidence: Any,
    llm_claim: VerdictLike = Verdict.INCONCLUSIVE,
) -> Verdict:
    """Mechanically derive the verdict from one piece of evidence.

    Accepts any object exposing `.success`, `.matches`, `.error` (the
    shape both `Evidence` from `result.py` and `ToolEvidence` from
    `adapters/base.py` provide). `llm_claim` is the verdict the LLM
    would have suggested; mechanical reality overrides it.

    Rules (each is a single line of code, not a separate hand-coded check):
      1. tool errored                               → INCONCLUSIVE
      2. claim=CONFIRMED but no matches             → REFUTED
      3. claim=REFUTED but matches present          → INCONCLUSIVE
      4. otherwise                                  → claim
    """
    if getattr(evidence, "error", "") and not getattr(evidence, "success", True):
        return Verdict.INCONCLUSIVE
    success = getattr(evidence, "success", True)
    if not success:
        return Verdict.INCONCLUSIVE
    matches = bool(getattr(evidence, "matches", []) or [])
    claim = _coerce(llm_claim)
    if claim is Verdict.CONFIRMED and not matches:
        return Verdict.REFUTED
    if claim is Verdict.REFUTED and matches:
        return Verdict.INCONCLUSIVE
    return claim


def aggregate(
    evidence_list: Iterable[Any],
    llm_claim: VerdictLike = Verdict.INCONCLUSIVE,
) -> Verdict:
    """Reduce a list of evidence to one verdict via meet.

    Empty list → INCONCLUSIVE (no mechanical evidence at all). Otherwise
    every adapter's per-evidence verdict is computed and joined with
    `meet`; agreement survives, disagreement collapses to bottom.
    """
    items = list(evidence_list)
    if not items:
        return Verdict.INCONCLUSIVE
    per = [verdict_from(e, llm_claim) for e in items]
    return reduce(meet, per)


__all__ = ["meet", "verdict_from", "aggregate", "VerdictLike"]
