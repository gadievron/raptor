"""Verdict combinators — the runner's downgrade rules in one place.

Two functions:

  verdict_from(evidence, llm_claim) -> Verdict
      The mechanical downgrade ladder. Same behaviour as the runner has
      today; `runner._evaluate_with_refinement` calls into here instead
      of inlining the rules at each evaluation path.

  aggregate(evidence_list, llm_claim) -> Verdict
      Combine multi-adapter evidence into one verdict. Used only by
      future iteration / multi-adapter callers; today's single-shot
      runner is a one-element case.

The three architectural invariants from PR #309's post-merge audit:

  1. tool failure                       → inconclusive
  2. claim=confirmed but no matches     → refuted
  3. claim=refuted but matches present  → inconclusive

When two adapters disagree on a hypothesis, `aggregate` collapses to
inconclusive. INCONCLUSIVE is the bottom of the lattice: it absorbs
disagreement and tool failures alike.
"""

from typing import Any
from collections.abc import Iterable

from .result import Verdict


_VALID = {"confirmed", "refuted", "inconclusive"}


def _coerce(v: Any) -> Verdict:
    """Default unknown values to inconclusive (the safe floor)."""
    return v if v in _VALID else "inconclusive"


def verdict_from(
    evidence: Any,
    llm_claim: Any = "inconclusive",
    *,
    polarity: str = "",
) -> Verdict:
    """Mechanically derive the verdict from one piece of evidence.

    Accepts any object exposing `.success` and `.matches` — both the
    `Evidence` dataclass from `result.py` and the `ToolEvidence`
    dataclass from `adapters/base.py` qualify. ``polarity`` is the
    hypothesis's declared reading (``Hypothesis.polarity``:
    "reachability" / "infeasibility" / "" undeclared) — set at
    formation time, before any tool output exists.

    Rules:

      - If the tool didn't run successfully: inconclusive. (The error
        text lives on the evidence object; we don't reproduce it here.)
      - A definitive SMT ``predicate_verdict`` with declared polarity is
        interpreted mechanically: SAT confirms reachability and refutes
        infeasibility; UNSAT gives the opposite directions. Model entry
        count and LLM judgement do not select the result. This establishes
        only the supplied predicates' mathematical feasibility.
      - If the tool ran, produced no matches, and the evidence carries
        ``empty_matches_conclusive`` (the adapter's assertion that the
        empty-match outcome is itself a definitive tool result — SMT
        ``unsat`` proving "these constraints are mutually exclusive"):
        the verdict DIRECTION comes from the declared polarity, never
        from the LLM's phrasing-aware reading of the hypothesis after
        seeing the tool output. unsat mechanically REFUTES a
        reachability-phrased claim and CONFIRMS an
        infeasibility-phrased one. With no declared polarity the proof
        is sound but its direction is unknowable mechanically, so an
        LLM "confirmed" downgrades to inconclusive (the claim is
        hint-tier — it must not mint a confirmed finding from zero
        matches); refuted/inconclusive claims pass through as before.
      - If the tool ran but produced no matches and the LLM claimed
        confirmed (no conclusiveness assertion): downgrade to refuted
        (you can't confirm without evidence).
      - If the tool ran and matches are present but the LLM claimed
        refuted: downgrade to inconclusive. (Matches deserve a human
        look even if the LLM dismissed them.)
      - Otherwise: pass the LLM claim through.
    """
    success = bool(getattr(evidence, "success", True))
    if not success:
        return "inconclusive"

    matches = bool(getattr(evidence, "matches", []) or [])
    claim = _coerce(llm_claim)

    # A SAT query can have an empty assignment (all guards tautological).
    # Model entries are display data, not the mathematical verdict. Use the
    # hypothesis's declared reading for both definitive SMT directions.
    predicate = getattr(evidence, "predicate_verdict", "")
    if getattr(evidence, "tool", "") == "smt" and predicate in ("sat", "unsat"):
        if polarity in ("reachability", "infeasibility"):
            supports = (predicate == "sat") == (polarity == "reachability")
            return "confirmed" if supports else "refuted"
        if predicate == "sat" and not matches:
            return "inconclusive"  # no declared direction; never infer UNSAT

    if not matches and bool(
        getattr(evidence, "empty_matches_conclusive", False)
    ):
        if polarity == "infeasibility":
            return "confirmed"
        if polarity == "reachability":
            return "refuted"
        return claim if claim != "confirmed" else "inconclusive"
    if claim == "confirmed" and not matches:
        return "refuted"
    if claim == "refuted" and matches:
        return "inconclusive"
    return claim


def aggregate(
    evidence_list: Iterable[Any],
    llm_claim: Any = "inconclusive",
    *,
    polarity: str = "",
) -> Verdict:
    """Combine multi-adapter evidence into one verdict.

    Empty list → inconclusive (no mechanical evidence at all).
    Otherwise: compute each adapter's per-evidence verdict via
    `verdict_from` (same ``polarity`` semantics), then meet them —
    equal verdicts compose, any disagreement collapses to
    inconclusive.
    """
    items = list(evidence_list)
    if not items:
        return "inconclusive"
    verdicts = [verdict_from(e, llm_claim, polarity=polarity) for e in items]
    out = verdicts[0]
    for v in verdicts[1:]:
        out = out if out == v else "inconclusive"
    return out


__all__ = ["aggregate", "verdict_from"]
