"""Verdict combinators — the runner's downgrade rules in one place.

Two functions:

  verdict_from(evidence, llm_claim) -> Verdict
      The mechanical downgrade ladder. Same behaviour as the runner has
      today; `runner._evaluate` calls into here instead of inlining the
      same three rules twice.

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

from typing import Any, Iterable

from .result import Verdict


_VALID = {"confirmed", "refuted", "inconclusive"}


def _coerce(v: Any) -> Verdict:
    """Default unknown values to inconclusive (the safe floor)."""
    return v if v in _VALID else "inconclusive"


def verdict_from(evidence: Any, llm_claim: Any = "inconclusive") -> Verdict:
    """Mechanically derive the verdict from one piece of evidence.

    Accepts any object exposing `.success` and `.matches` — both the
    `Evidence` dataclass from `result.py` and the `ToolEvidence`
    dataclass from `adapters/base.py` qualify.

    Behaviour matches the runner's existing logic exactly:

      - If the tool didn't run successfully: inconclusive. (The error
        text lives on the evidence object; we don't reproduce it here.)
      - If the tool ran but produced no matches and the LLM claimed
        confirmed: downgrade to refuted. (You can't confirm without
        evidence.)
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

    if claim == "confirmed" and not matches:
        return "refuted"
    if claim == "refuted" and matches:
        return "inconclusive"
    return claim


def aggregate(
    evidence_list: Iterable[Any],
    llm_claim: Any = "inconclusive",
) -> Verdict:
    """Combine multi-adapter evidence into one verdict.

    Empty list → inconclusive (no mechanical evidence at all).
    Otherwise: compute each adapter's per-evidence verdict via
    `verdict_from`, then meet them — equal verdicts compose, any
    disagreement collapses to inconclusive.
    """
    items = list(evidence_list)
    if not items:
        return "inconclusive"
    verdicts = [verdict_from(e, llm_claim) for e in items]
    out = verdicts[0]
    for v in verdicts[1:]:
        out = out if out == v else "inconclusive"
    return out


__all__ = ["verdict_from", "aggregate"]
