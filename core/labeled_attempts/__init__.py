"""Finding-keyed append-only corpus of oracle-verified attempts.

A ``LabeledAttempt`` records one attempt by some producer (LLM-driven
analysis, classifier, fuzzer, manual operator) to act on a finding,
together with the oracle evidence (sandbox / CodeQL / web) and the
resulting outcome.

The substrate is producer-agnostic: any RAPTOR command that runs an
attempt against a finding and adjudicates the outcome can write records
into the same store. Records are keyed by a stable
:func:`compute_finding_signature` hash (over CWE + file + function + line
+ vuln_type) so rename and move refactors don't break cross-run linking.

See ``types.py`` for the schema, ``store.py`` for the storage layer,
``retrieval.py`` for exemplar lookup, ``view.py`` for the
:class:`VerifiedOutcome` projection used by prompt assembly.
"""

from .annotation import set_failure_mode
from .pruning import PruneReport, prune_pool
from .retrieval import (
    RetrievedExemplar,
    recent_failure_summary,
    retrieve_exemplars,
)
from .store import (
    bundled_corpus_path,
    find_by_cwe,
    find_by_finding_signature,
    global_pool_path,
    project_pool_path,
    read_all,
    write,
)
from .types import (
    CodeQLEvidence,
    FailureMode,
    LabeledAttempt,
    Outcome,
    SandboxEvidence,
    WebEvidence,
    compute_finding_signature,
)
from .view import (
    Oracle,
    OutcomeStatus,
    ScoredOutcome,
    VerifiedOutcome,
    collect_outcomes,
    exemplar_block_for_finding,
    from_barrier_synthesis,
    from_witness,
    rank_outcomes_for_finding,
    render_outcome_summary,
    render_verified_exemplars,
)

__all__ = [
    # Schema
    "CodeQLEvidence",
    "FailureMode",
    "LabeledAttempt",
    "Outcome",
    "PruneReport",
    "RetrievedExemplar",
    "SandboxEvidence",
    "WebEvidence",
    "compute_finding_signature",
    # Store
    "bundled_corpus_path",
    "find_by_cwe",
    "find_by_finding_signature",
    "global_pool_path",
    "project_pool_path",
    "prune_pool",
    "read_all",
    "recent_failure_summary",
    "retrieve_exemplars",
    "set_failure_mode",
    "write",
    # View — VerifiedOutcome projection (consumer-facing prompt API)
    "Oracle",
    "OutcomeStatus",
    "ScoredOutcome",
    "VerifiedOutcome",
    "collect_outcomes",
    "exemplar_block_for_finding",
    "from_barrier_synthesis",
    "from_witness",
    "rank_outcomes_for_finding",
    "render_outcome_summary",
    "render_verified_exemplars",
]
