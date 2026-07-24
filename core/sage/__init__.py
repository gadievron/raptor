"""SAGE persistent memory integration for RAPTOR."""

from .config import SageConfig
from .client import SageClient
from .hooks import (
    # CodeQL build flags (mechanical inference from prior outcomes)
    recall_context_for_codeql_build,
    store_codeql_build_reliability,
    infer_codeql_build_from_sage_recall_row,
    # Fuzzing strategy (mechanical AFL flag inference)
    recall_context_for_fuzzing_strategy,
    store_fuzzing_strategy_outcome,
    # SCA (mechanical short-circuit)
    recall_context_for_sca,
    store_sca_outcomes,
    # Finding verdict — cross-run FP suppression
    recall_prior_finding_verdict,
    store_finding_verdict,
    compute_finding_source_hash,
)

__all__ = [
    "SageConfig",
    "SageClient",
    "recall_context_for_codeql_build",
    "store_codeql_build_reliability",
    "infer_codeql_build_from_sage_recall_row",
    "recall_context_for_fuzzing_strategy",
    "store_fuzzing_strategy_outcome",
    "recall_context_for_sca",
    "store_sca_outcomes",
    "recall_prior_finding_verdict",
    "store_finding_verdict",
    "compute_finding_source_hash",
]
