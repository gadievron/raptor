"""ZKPoX Tier 0/1 — witness eligibility classification.

A ZKPoX (Zero-Knowledge Proof of Exploit) proves "I possess an
input that makes binary H exhibit outcome O" without revealing the
input. Before any proving can happen, a witness has to *qualify* as
a candidate. This module is that classifier.

Eligibility is **free** (the package's trigger model): it reads the
witness record and checks fields — no execution, no artifacts. It's
surfaced in end-of-run summaries the way witness counts are
(#607), so operators see "N of M witnesses are ZKPoX-eligible"
without asking for anything heavier.

The full tier model + free/on-request split lives in the package
docstring (``packages/zkpox/__init__.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.witness.types import Witness, WitnessOutcome


# Outcomes that represent an *observed security-relevant event* —
# the bug actually fired. These are the only outcomes worth proving:
# a NOT_RUN / NO_OBVIOUS_EFFECT / UNKNOWN witness has nothing to
# prove ("I have bytes that make the binary do nothing" is not a
# proof of exploit).
_PROVABLE_OUTCOMES = frozenset({
    WitnessOutcome.EXIT_SIGNAL,
    WitnessOutcome.SANITIZER_REPORT,
    WitnessOutcome.FLAG_CAPTURED,
})


@dataclass(frozen=True)
class ZKPoXEligibility:
    """Result of classifying one witness for ZKPoX candidacy."""
    witness_hash: str
    eligible: bool
    reason: str
    # The strongest tier this witness could *reach* given its
    # current record. Tier 0/1 always (if eligible); 1.5 requires a
    # runnable target artefact, which eligibility can't confirm on
    # its own (the artefact lives outside the witness store) — so we
    # report the ceiling as "0/1" here and let the reproduction step
    # confirm 1.5 when the operator supplies the artefact.
    max_tier_from_record: str = "none"


def is_zkpox_eligible(witness: Witness) -> ZKPoXEligibility:
    """Classify a single ``Witness`` for ZKPoX candidacy.

    A witness is eligible iff ALL hold:

      1. ``observed_outcome`` is a *provable* outcome — the bug was
         actually observed (EXIT_SIGNAL / SANITIZER_REPORT /
         FLAG_CAPTURED). NOT_RUN / NO_OBVIOUS_EFFECT / UNKNOWN have
         nothing to prove.
      2. A target artefact hash is present — at least one of
         ``target_binary_hash`` or ``target_source_hash``. Without
         a concrete target, there's no "binary H" to prove against.

    ``bytes_len`` of 0 (empty witness) is *not* a hard
    disqualifier — an empty input that triggers a crash is a valid
    (if unusual) proof target — but it's noted in the reason so
    operators can eyeball it.

    Returns a :class:`ZKPoXEligibility`. Never raises — a witness
    with surprising field shapes is reported ineligible with the
    reason, not an exception.
    """
    h = witness.bytes_hash

    outcome = witness.observed_outcome
    if outcome not in _PROVABLE_OUTCOMES:
        return ZKPoXEligibility(
            witness_hash=h,
            eligible=False,
            reason=(
                f"outcome {outcome.value!r} is not provable "
                f"(need one of: "
                f"{sorted(o.value for o in _PROVABLE_OUTCOMES)})"
            ),
        )

    if not (witness.target_binary_hash or witness.target_source_hash):
        return ZKPoXEligibility(
            witness_hash=h,
            eligible=False,
            reason=(
                "no target artefact hash "
                "(need target_binary_hash or target_source_hash) — "
                "nothing concrete to prove against"
            ),
        )

    note = ""
    if witness.bytes_len == 0:
        note = " (note: zero-length witness — verify the empty input "
        note += "genuinely triggers the outcome)"

    return ZKPoXEligibility(
        witness_hash=h,
        eligible=True,
        reason=f"provable outcome {outcome.value!r} + target hash present{note}",
        max_tier_from_record="0/1",
    )


def summarize_eligibility(witnesses) -> dict:
    """Classify an iterable of witnesses; return aggregate counts
    for the free end-of-run surfacing.

    Returns::

        {
          "total": int,
          "eligible": int,
          "ineligible": int,
          "by_reason": {<reason-class>: count, ...},
          "eligible_hashes": [<bytes_hash>, ...],
        }

    ``by_reason`` keys are coarse reason-classes (not the full
    per-witness strings) so the summary stays compact:
    ``provable`` / ``outcome_not_provable`` / ``no_target``.
    """
    total = 0
    eligible = 0
    by_reason: dict = {}
    eligible_hashes = []

    for w in witnesses:
        total += 1
        verdict = is_zkpox_eligible(w)
        if verdict.eligible:
            eligible += 1
            eligible_hashes.append(verdict.witness_hash)
            key = "provable"
        elif "not provable" in verdict.reason:
            key = "outcome_not_provable"
        else:
            key = "no_target"
        by_reason[key] = by_reason.get(key, 0) + 1

    return {
        "total": total,
        "eligible": eligible,
        "ineligible": total - eligible,
        "by_reason": by_reason,
        "eligible_hashes": eligible_hashes,
    }


def render_eligibility_summary(
    witnesses,
    *,
    indent: str = "   ",
) -> Optional[str]:
    """Console block for the free end-of-run surfacing; ``None``
    when there are no witnesses (caller skips printing a header).

        ZKPoX-eligible witnesses: 2 / 7
           provable:             2
           outcome_not_provable: 4
           no_target:            1

    Mirrors the cadence of
    ``core.reporting.witnesses.render_witness_summary``.
    """
    s = summarize_eligibility(witnesses)
    if s["total"] == 0:
        return None
    lines = [
        f"ZKPoX-eligible witnesses: {s['eligible']} / {s['total']}",
    ]
    for key in ("provable", "outcome_not_provable", "no_target"):
        if key in s["by_reason"]:
            lines.append(f"{indent}{key}: {s['by_reason'][key]}")
    return "\n".join(lines)
