"""Rank witnesses by how well they match a given finding.

Stage E (and any future consumer that wants "the most relevant
witness for this finding") needs to pick from the witness set
discovered by :mod:`core.witness.discovery`. The matching is
purely structural — no LLM judgment — driven by the
``outcome_detail`` fields the witness producers populate.

Ranking (higher score → better match):

  10  Exact finding-id match
       ``outcome_detail["finding_id"] == finding.id``
       The producer (e.g. crash_agent / agent.py) recorded this
       witness specifically for this finding.

  7   CWE + file match
       ``outcome_detail["cwe_id"] == finding.cwe_id`` AND
       ``outcome_detail["file_path"] == finding.file``
       Same bug class, same source file — strong proxy when ids
       differ (e.g. /fuzz witness vs /validate finding-id).

  4   File match
       ``outcome_detail["file_path"] == finding.file``
       Same source file, possibly different CWE — useful when
       one file has multiple findings.

  2   Same target binary
       The witness's ``target_binary_hash`` matches a finding's
       binary. Fuzz witnesses lean on this (no source-level ids
       — they were produced before any LLM classification).

  0   No structured signal
       Falls through; consumer can still use the witness as a
       last-resort but should treat the verdict cautiously.

Ties broken by:

  1. Source preference: ``LLM_EMIT_RUN`` > ``FUZZ`` > others
     (LLM emit was synthesised against the finding's bug class
     explicitly; fuzz is generic crash evidence).
  2. Observed-outcome richness: ``SANITIZER_REPORT`` >
     ``EXIT_SIGNAL`` > others (sanitizer reports identify the
     bug class; raw signals are correct but less specific).
  3. ``bytes_hash`` lex order (deterministic tie-breaker).

Note: the score thresholds are deliberately conservative. A
finding may have zero matches — that's a "no witness available"
signal, not an error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.witness.types import Witness, WitnessOutcome, WitnessSource


@dataclass(frozen=True)
class WitnessMatch:
    """A scored witness candidate for a given finding."""
    witness: Witness
    store_root: Any  # Path, but Any to avoid import cycle
    score: int
    reason: str

    @property
    def is_real(self) -> bool:
        """True iff the match score is above the "no structured
        signal" threshold. Consumers may want to skip score-0
        matches entirely."""
        return self.score > 0


def _source_priority(src: WitnessSource) -> int:
    if src is WitnessSource.LLM_EMIT_RUN:
        return 2
    if src is WitnessSource.FUZZ:
        return 1
    return 0


def _outcome_priority(outcome: WitnessOutcome) -> int:
    if outcome is WitnessOutcome.SANITIZER_REPORT:
        return 3
    if outcome is WitnessOutcome.EXIT_SIGNAL:
        return 2
    if outcome is WitnessOutcome.FLAG_CAPTURED:
        return 4  # rare but most-specific
    return 1


def score_witness_for_finding(
    witness: Witness,
    finding: Dict[str, Any],
) -> Tuple[int, str]:
    """Return ``(score, reason)`` for one witness against one
    finding. Consumers loop this over a witness list and pick
    the maxima via :func:`best_match_for_finding`."""
    detail = witness.outcome_detail if isinstance(witness.outcome_detail, dict) else {}

    finding_id = finding.get("id")
    finding_cwe = finding.get("cwe_id") or finding.get("cwe")
    finding_file = finding.get("file") or finding.get("file_path")
    binary_path = (
        finding.get("feasibility", {}).get("binary_path")
        if isinstance(finding.get("feasibility"), dict)
        else None
    )

    if finding_id and detail.get("finding_id") == finding_id:
        return 10, "exact finding-id match"

    if (finding_cwe and detail.get("cwe_id") == finding_cwe
            and finding_file and detail.get("file_path") == finding_file):
        return 7, "cwe + file match"

    if finding_file and detail.get("file_path") == finding_file:
        return 4, "file match"

    # Binary-hash fallback for fuzz witnesses (no finding_id /
    # source structure). We don't hash the finding's binary path
    # here — caller's responsibility — but if a target_binary_hash
    # exists at all on the witness, that's evidence it ran
    # against *some* binary, which is more than zero signal.
    if witness.target_binary_hash and binary_path:
        return 2, "same target binary (hash-pending)"

    return 0, "no structured signal"


def best_match_for_finding(
    witnesses: Iterable[Tuple[Any, Witness]],
    finding: Dict[str, Any],
) -> Optional[WitnessMatch]:
    """Pick the best-ranked witness for ``finding`` from an
    iterable of ``(store_root, Witness)`` pairs.

    Returns ``None`` when no candidate scores above 0 (i.e. no
    structured signal — caller should treat as "no witness").

    Tie-break order: source > outcome > bytes_hash. See module
    docstring for rationale.
    """
    candidates: List[WitnessMatch] = []
    for store_root, w in witnesses:
        score, reason = score_witness_for_finding(w, finding)
        if score == 0:
            continue
        candidates.append(WitnessMatch(
            witness=w, store_root=store_root,
            score=score, reason=reason,
        ))

    if not candidates:
        return None

    candidates.sort(
        key=lambda m: (
            -m.score,
            -_source_priority(m.witness.source),
            -_outcome_priority(m.witness.observed_outcome),
            m.witness.bytes_hash,
        ),
    )
    return candidates[0]
