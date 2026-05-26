"""Collect + rank :class:`VerifiedOutcome` records.

``collect_outcomes`` builds the unified verified-outcome view for a run (and
its project siblings) from the witness backend. ``rank_outcomes_for_finding``
is the retrieval primitive: given a finding, return its nearest verified
outcomes -- the substrate an exemplar-injection wire reads.

Scoring mirrors ``core.witness.matching`` (finding-id 10, cwe+file 7, file 4)
so the two stay consistent; the difference is this operates over the
normalised, oracle-agnostic :class:`VerifiedOutcome` rather than a raw
``Witness``. A pure cwe-only tier (2) is added because a same-class exemplar
from another file is still useful priming material for retrieval.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.verified_outcome.adapters import from_witness
from core.verified_outcome.types import OutcomeStatus, VerifiedOutcome
from core.witness import discover_witness_stores, iter_visible_witnesses


def collect_outcomes(
    output_dir: Optional[Path],
    *,
    project_root: Optional[Path] = None,
) -> List[VerifiedOutcome]:
    """Discover every witness store visible to a run (and its project
    siblings) and project each witness onto a :class:`VerifiedOutcome`.

    Witness-backed only for now; the CodeQL/trust and ``/web`` backends
    append here as their adapters land. Never raises -- discovery and
    iteration are best-effort (see ``core.witness.discovery``).
    """
    stores = discover_witness_stores(output_dir, project_root=project_root)
    return [from_witness(w) for _root, w in iter_visible_witnesses(stores)]


@dataclass(frozen=True)
class ScoredOutcome:
    """A verified outcome scored against a particular finding."""

    outcome: VerifiedOutcome
    score: int
    reason: str


def _score_outcome(
    outcome: VerifiedOutcome, finding: Dict[str, Any],
) -> Tuple[int, str]:
    finding_id = finding.get("id")
    finding_cwe = finding.get("cwe_id") or finding.get("cwe")
    finding_file = finding.get("file") or finding.get("file_path")

    if finding_id and outcome.finding_id and outcome.finding_id == finding_id:
        return 10, "exact finding-id match"
    if (finding_cwe and outcome.cwe_id == finding_cwe
            and finding_file and outcome.file == finding_file):
        return 7, "cwe + file match"
    if finding_file and outcome.file == finding_file:
        return 4, "file match"
    if finding_cwe and outcome.cwe_id == finding_cwe:
        return 2, "cwe match"
    return 0, "no structured signal"


def rank_outcomes_for_finding(
    outcomes: Iterable[VerifiedOutcome],
    finding: Dict[str, Any],
    *,
    top_k: int = 3,
    statuses: Tuple[OutcomeStatus, ...] = (OutcomeStatus.VERIFIED,),
) -> List[ScoredOutcome]:
    """Return the ``top_k`` outcomes most relevant to ``finding``.

    Filters to ``statuses`` first (default: only VERIFIED -- exemplar
    retrieval wants *successful* outcomes to prime on; pass a wider set for a
    full verified-status view). Drops score-0 (no structured signal). Ties
    broken by reproducible-first, then recency, then a deterministic
    evidence-hash key.
    """
    scored: List[ScoredOutcome] = []
    for o in outcomes:
        if statuses and o.status not in statuses:
            continue
        score, reason = _score_outcome(o, finding)
        if score == 0:
            continue
        scored.append(ScoredOutcome(outcome=o, score=score, reason=reason))

    scored.sort(
        key=lambda s: (
            -s.score,
            0 if s.outcome.reproducible else 1,
            -s.outcome.timestamp.timestamp(),
            str(s.outcome.evidence.get("witness_bytes_hash", "")),
        ),
    )
    return scored[:top_k]
