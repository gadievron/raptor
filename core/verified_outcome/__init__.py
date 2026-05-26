"""Oracle-polymorphic verified-outcome record + retrieval.

A shared, Finding-keyed spine that unifies the verification signals RAPTOR's
oracles produce (sandbox / fuzzer / CodeQL / web / manual), so verified
status is queryable in one place rather than scattered across per-producer
fields. See ``types.py`` for the data model and rationale.
"""

from core.verified_outcome.adapters import from_barrier_synthesis, from_witness
from core.verified_outcome.collect import (
    ScoredOutcome,
    collect_outcomes,
    rank_outcomes_for_finding,
)
from core.verified_outcome.exemplars import (
    exemplar_block_for_finding,
    render_verified_exemplars,
)
from core.verified_outcome.render import render_outcome_summary
from core.verified_outcome.types import Oracle, OutcomeStatus, VerifiedOutcome

__all__ = [
    "Oracle",
    "OutcomeStatus",
    "VerifiedOutcome",
    "from_witness",
    "from_barrier_synthesis",
    "collect_outcomes",
    "rank_outcomes_for_finding",
    "ScoredOutcome",
    "render_verified_exemplars",
    "exemplar_block_for_finding",
    "render_outcome_summary",
]
